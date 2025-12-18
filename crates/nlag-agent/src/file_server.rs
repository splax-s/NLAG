//! File Server Mode
//!
//! Serves static files directly from the local filesystem without requiring
//! a separate web server. Supports:
//! - Directory listing
//! - MIME type detection
//! - Range requests (for video streaming)
//! - Caching headers
//! - Index file fallback (index.html)
//! - Hidden file filtering
//!
//! ## Usage
//!
//! ```bash
//! nlag expose file:///path/to/directory
//! nlag expose file:///path/to/directory --index index.html
//! nlag expose file:///path/to/directory --no-listing
//! ```

use std::collections::HashMap;
use std::fs::{self, File, Metadata};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, warn};

/// File server errors
#[derive(Debug, Error)]
pub enum FileServerError {
    #[error("File not found: {0}")]
    NotFound(String),
    
    #[error("Access denied: {0}")]
    AccessDenied(String),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Invalid path: {0}")]
    InvalidPath(String),
    
    #[error("Path traversal detected")]
    PathTraversal,
}

pub type Result<T> = std::result::Result<T, FileServerError>;

/// File server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileServerConfig {
    /// Root directory to serve
    pub root: PathBuf,
    
    /// Index file names to look for
    #[serde(default = "default_index_files")]
    pub index_files: Vec<String>,
    
    /// Enable directory listing
    #[serde(default = "default_true")]
    pub directory_listing: bool,
    
    /// Show hidden files (starting with .)
    #[serde(default)]
    pub show_hidden: bool,
    
    /// Enable range requests
    #[serde(default = "default_true")]
    pub enable_range: bool,
    
    /// Cache-Control max-age in seconds (0 = no-cache)
    #[serde(default = "default_cache_age")]
    pub cache_max_age: u64,
    
    /// Custom MIME types (extension -> mime)
    #[serde(default)]
    pub mime_types: HashMap<String, String>,
    
    /// Default MIME type for unknown extensions
    #[serde(default = "default_mime")]
    pub default_mime: String,
    
    /// Enable ETag generation
    #[serde(default = "default_true")]
    pub enable_etag: bool,
    
    /// Compress responses (requires gzip/brotli support)
    #[serde(default)]
    pub compress: bool,
    
    /// Custom 404 page path (relative to root)
    #[serde(default)]
    pub not_found_page: Option<String>,
}

fn default_index_files() -> Vec<String> {
    vec!["index.html".to_string(), "index.htm".to_string()]
}

fn default_true() -> bool { true }
fn default_cache_age() -> u64 { 3600 } // 1 hour
fn default_mime() -> String { "application/octet-stream".to_string() }

impl Default for FileServerConfig {
    fn default() -> Self {
        Self {
            root: PathBuf::from("."),
            index_files: default_index_files(),
            directory_listing: true,
            show_hidden: false,
            enable_range: true,
            cache_max_age: default_cache_age(),
            mime_types: HashMap::new(),
            default_mime: default_mime(),
            enable_etag: true,
            compress: false,
            not_found_page: None,
        }
    }
}

impl FileServerConfig {
    /// Create a new file server config for a directory
    pub fn new<P: AsRef<Path>>(root: P) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            ..Default::default()
        }
    }
    
    /// Disable directory listing
    pub fn no_listing(mut self) -> Self {
        self.directory_listing = false;
        self
    }
    
    /// Set custom index files
    pub fn with_index<I: IntoIterator<Item = S>, S: Into<String>>(mut self, files: I) -> Self {
        self.index_files = files.into_iter().map(|s| s.into()).collect();
        self
    }
    
    /// Set cache max-age
    pub fn with_cache_age(mut self, seconds: u64) -> Self {
        self.cache_max_age = seconds;
        self
    }
}

/// HTTP response from file server
#[derive(Debug)]
pub struct FileResponse {
    /// HTTP status code
    pub status: u16,
    /// Response headers
    pub headers: HashMap<String, String>,
    /// Response body
    pub body: Vec<u8>,
}

impl FileResponse {
    /// Create a new response
    pub fn new(status: u16) -> Self {
        Self {
            status,
            headers: HashMap::new(),
            body: Vec::new(),
        }
    }
    
    /// Add a header
    pub fn header(mut self, key: &str, value: &str) -> Self {
        self.headers.insert(key.to_string(), value.to_string());
        self
    }
    
    /// Set body
    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }
    
    /// Create a 404 response
    pub fn not_found(path: &str) -> Self {
        let body = format!(
            r#"<!DOCTYPE html>
<html>
<head><title>404 Not Found</title></head>
<body>
<h1>404 Not Found</h1>
<p>The requested path <code>{}</code> was not found.</p>
</body>
</html>"#,
            html_escape(path)
        );
        
        Self::new(404)
            .header("Content-Type", "text/html; charset=utf-8")
            .header("Content-Length", &body.len().to_string())
            .body(body.into_bytes())
    }
    
    /// Create a 403 response
    pub fn forbidden(path: &str) -> Self {
        let body = format!(
            r#"<!DOCTYPE html>
<html>
<head><title>403 Forbidden</title></head>
<body>
<h1>403 Forbidden</h1>
<p>Access to <code>{}</code> is denied.</p>
</body>
</html>"#,
            html_escape(path)
        );
        
        Self::new(403)
            .header("Content-Type", "text/html; charset=utf-8")
            .header("Content-Length", &body.len().to_string())
            .body(body.into_bytes())
    }
}

/// File server instance
pub struct FileServer {
    config: FileServerConfig,
}

impl FileServer {
    /// Create a new file server
    pub fn new(config: FileServerConfig) -> Result<Self> {
        // Validate root directory exists
        if !config.root.exists() {
            return Err(FileServerError::NotFound(
                config.root.display().to_string()
            ));
        }
        
        if !config.root.is_dir() {
            return Err(FileServerError::InvalidPath(
                "Root must be a directory".to_string()
            ));
        }
        
        info!("File server initialized for: {}", config.root.display());
        
        Ok(Self { config })
    }
    
    /// Handle an HTTP request
    pub fn handle_request(
        &self,
        method: &str,
        path: &str,
        headers: &HashMap<String, String>,
    ) -> FileResponse {
        // Only allow GET and HEAD
        if method != "GET" && method != "HEAD" {
            return FileResponse::new(405)
                .header("Allow", "GET, HEAD")
                .header("Content-Length", "0");
        }
        
        // Decode URL path
        let decoded_path = match urlencoding::decode(path) {
            Ok(p) => p.into_owned(),
            Err(_) => return FileResponse::not_found(path),
        };
        
        // Resolve file path
        let file_path = match self.resolve_path(&decoded_path) {
            Ok(p) => p,
            Err(FileServerError::NotFound(_)) => {
                return self.handle_not_found(&decoded_path);
            }
            Err(FileServerError::PathTraversal) => {
                return FileResponse::forbidden(&decoded_path);
            }
            Err(FileServerError::AccessDenied(_)) => {
                return FileResponse::forbidden(&decoded_path);
            }
            Err(e) => {
                warn!("File server error: {}", e);
                return FileResponse::new(500)
                    .header("Content-Type", "text/plain")
                    .body(b"Internal Server Error".to_vec());
            }
        };
        
        // Check if it's a directory
        if file_path.is_dir() {
            // Try index files
            for index in &self.config.index_files {
                let index_path = file_path.join(index);
                if index_path.exists() && index_path.is_file() {
                    return self.serve_file(&index_path, method, headers);
                }
            }
            
            // Directory listing
            if self.config.directory_listing {
                return self.serve_directory(&file_path, &decoded_path);
            } else {
                return FileResponse::forbidden(&decoded_path);
            }
        }
        
        // Serve the file
        self.serve_file(&file_path, method, headers)
    }
    
    /// Resolve a URL path to a filesystem path
    fn resolve_path(&self, url_path: &str) -> Result<PathBuf> {
        // Normalize path
        let clean_path = url_path.trim_start_matches('/');
        
        // Build full path
        let full_path = self.config.root.join(clean_path);
        
        // Canonicalize to prevent path traversal
        let canonical = full_path.canonicalize()
            .map_err(|_| FileServerError::NotFound(url_path.to_string()))?;
        
        let root_canonical = self.config.root.canonicalize()
            .map_err(|e| FileServerError::IoError(e))?;
        
        // Check path is within root
        if !canonical.starts_with(&root_canonical) {
            return Err(FileServerError::PathTraversal);
        }
        
        // Check for hidden files
        if !self.config.show_hidden {
            for component in canonical.strip_prefix(&root_canonical).unwrap_or(&canonical).components() {
                if let std::path::Component::Normal(name) = component {
                    if name.to_string_lossy().starts_with('.') {
                        return Err(FileServerError::AccessDenied(
                            "Hidden files not accessible".to_string()
                        ));
                    }
                }
            }
        }
        
        Ok(canonical)
    }
    
    /// Serve a file
    fn serve_file(
        &self,
        path: &Path,
        method: &str,
        headers: &HashMap<String, String>,
    ) -> FileResponse {
        // Get file metadata
        let metadata = match fs::metadata(path) {
            Ok(m) => m,
            Err(_) => return FileResponse::not_found(&path.display().to_string()),
        };
        
        let file_size = metadata.len();
        let mime_type = self.get_mime_type(path);
        let etag = self.generate_etag(&metadata, path);
        let last_modified = self.get_last_modified(&metadata);
        
        // Check If-None-Match (ETag)
        if self.config.enable_etag {
            if let Some(if_none_match) = headers.get("if-none-match") {
                if if_none_match.trim_matches('"') == etag {
                    return FileResponse::new(304)
                        .header("ETag", &format!("\"{}\"", etag));
                }
            }
        }
        
        // Check If-Modified-Since
        if let Some(if_modified) = headers.get("if-modified-since") {
            if let Some(ref lm) = last_modified {
                if if_modified == lm {
                    return FileResponse::new(304)
                        .header("Last-Modified", lm);
                }
            }
        }
        
        // Parse Range header
        let range = if self.config.enable_range {
            headers.get("range").and_then(|r| parse_range(r, file_size))
        } else {
            None
        };
        
        // Build response
        let mut response = if range.is_some() {
            FileResponse::new(206)
        } else {
            FileResponse::new(200)
        };
        
        response = response
            .header("Content-Type", &mime_type)
            .header("Accept-Ranges", if self.config.enable_range { "bytes" } else { "none" });
        
        if self.config.enable_etag {
            response = response.header("ETag", &format!("\"{}\"", etag));
        }
        
        if let Some(ref lm) = last_modified {
            response = response.header("Last-Modified", lm);
        }
        
        if self.config.cache_max_age > 0 {
            response = response.header(
                "Cache-Control",
                &format!("public, max-age={}", self.config.cache_max_age)
            );
        } else {
            response = response.header("Cache-Control", "no-cache");
        }
        
        // HEAD request - no body
        if method == "HEAD" {
            return response.header("Content-Length", &file_size.to_string());
        }
        
        // Read file content
        let body = match self.read_file(path, range) {
            Ok((data, content_range)) => {
                if let Some(cr) = content_range {
                    response = response.header("Content-Range", &cr);
                }
                data
            }
            Err(e) => {
                warn!("Failed to read file {}: {}", path.display(), e);
                return FileResponse::new(500)
                    .header("Content-Type", "text/plain")
                    .body(b"Failed to read file".to_vec());
            }
        };
        
        response
            .header("Content-Length", &body.len().to_string())
            .body(body)
    }
    
    /// Read file contents (with optional range)
    fn read_file(&self, path: &Path, range: Option<(u64, u64)>) -> Result<(Vec<u8>, Option<String>)> {
        let mut file = File::open(path)?;
        let file_size = file.metadata()?.len();
        
        if let Some((start, end)) = range {
            let length = end - start + 1;
            file.seek(SeekFrom::Start(start))?;
            
            let mut buffer = vec![0u8; length as usize];
            file.read_exact(&mut buffer)?;
            
            let content_range = format!("bytes {}-{}/{}", start, end, file_size);
            Ok((buffer, Some(content_range)))
        } else {
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer)?;
            Ok((buffer, None))
        }
    }
    
    /// Serve directory listing
    fn serve_directory(&self, path: &Path, url_path: &str) -> FileResponse {
        let entries = match fs::read_dir(path) {
            Ok(e) => e,
            Err(_) => return FileResponse::forbidden(url_path),
        };
        
        let mut files: Vec<DirEntry> = Vec::new();
        
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            
            // Skip hidden files if configured
            if !self.config.show_hidden && name.starts_with('.') {
                continue;
            }
            
            let metadata = entry.metadata().ok();
            let is_dir = metadata.as_ref().map(|m| m.is_dir()).unwrap_or(false);
            let size = metadata.as_ref().map(|m| m.len()).unwrap_or(0);
            let modified = metadata.as_ref()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                .map(|d| d.as_secs());
            
            files.push(DirEntry {
                name,
                is_dir,
                size,
                modified,
            });
        }
        
        // Sort: directories first, then by name
        files.sort_by(|a, b| {
            match (a.is_dir, b.is_dir) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
            }
        });
        
        let html = self.render_directory_listing(url_path, &files);
        
        FileResponse::new(200)
            .header("Content-Type", "text/html; charset=utf-8")
            .header("Content-Length", &html.len().to_string())
            .body(html.into_bytes())
    }
    
    /// Render directory listing HTML
    fn render_directory_listing(&self, path: &str, entries: &[DirEntry]) -> String {
        let mut html = format!(
            r#"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Index of {}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 2rem; }}
h1 {{ color: #333; border-bottom: 1px solid #ddd; padding-bottom: 0.5rem; }}
table {{ border-collapse: collapse; width: 100%; max-width: 800px; }}
th, td {{ text-align: left; padding: 0.5rem 1rem; }}
th {{ background: #f5f5f5; }}
tr:hover {{ background: #f9f9f9; }}
a {{ color: #0066cc; text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
.dir {{ font-weight: bold; }}
.size {{ color: #666; text-align: right; }}
.date {{ color: #666; }}
</style>
</head>
<body>
<h1>Index of {}</h1>
<table>
<tr><th>Name</th><th class="size">Size</th><th class="date">Modified</th></tr>
"#,
            html_escape(path),
            html_escape(path)
        );
        
        // Add parent directory link
        if path != "/" {
            let parent = Path::new(path)
                .parent()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| "/".to_string());
            html.push_str(&format!(
                r#"<tr><td><a href="{}">../</a></td><td class="size">-</td><td class="date">-</td></tr>
"#,
                if parent.is_empty() { "/" } else { &parent }
            ));
        }
        
        for entry in entries {
            let display_name = if entry.is_dir {
                format!("{}/", entry.name)
            } else {
                entry.name.clone()
            };
            
            let href = format!(
                "{}/{}",
                path.trim_end_matches('/'),
                urlencoding::encode(&entry.name)
            );
            
            let size = if entry.is_dir {
                "-".to_string()
            } else {
                format_size(entry.size)
            };
            
            let modified = entry.modified
                .map(|ts| {
                    DateTime::<Utc>::from_timestamp(ts as i64, 0)
                        .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
                        .unwrap_or_else(|| "-".to_string())
                })
                .unwrap_or_else(|| "-".to_string());
            
            let class = if entry.is_dir { "dir" } else { "" };
            
            html.push_str(&format!(
                r#"<tr><td class="{}"><a href="{}">{}</a></td><td class="size">{}</td><td class="date">{}</td></tr>
"#,
                class,
                html_escape(&href),
                html_escape(&display_name),
                size,
                modified
            ));
        }
        
        html.push_str("</table>\n</body>\n</html>");
        html
    }
    
    /// Handle 404 with custom page if configured
    fn handle_not_found(&self, path: &str) -> FileResponse {
        if let Some(ref not_found_page) = self.config.not_found_page {
            let page_path = self.config.root.join(not_found_page);
            if page_path.exists() {
                if let Ok(content) = fs::read(&page_path) {
                    return FileResponse::new(404)
                        .header("Content-Type", self.get_mime_type(&page_path).as_str())
                        .header("Content-Length", &content.len().to_string())
                        .body(content);
                }
            }
        }
        
        FileResponse::not_found(path)
    }
    
    /// Get MIME type for a file
    fn get_mime_type(&self, path: &Path) -> String {
        let ext = path.extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_lowercase())
            .unwrap_or_default();
        
        // Check custom types first
        if let Some(mime) = self.config.mime_types.get(&ext) {
            return mime.clone();
        }
        
        // Built-in types
        match ext.as_str() {
            // Text
            "html" | "htm" => "text/html; charset=utf-8",
            "css" => "text/css; charset=utf-8",
            "js" | "mjs" => "application/javascript; charset=utf-8",
            "json" => "application/json; charset=utf-8",
            "xml" => "application/xml; charset=utf-8",
            "txt" => "text/plain; charset=utf-8",
            "md" => "text/markdown; charset=utf-8",
            "csv" => "text/csv; charset=utf-8",
            
            // Images
            "png" => "image/png",
            "jpg" | "jpeg" => "image/jpeg",
            "gif" => "image/gif",
            "svg" => "image/svg+xml",
            "ico" => "image/x-icon",
            "webp" => "image/webp",
            "avif" => "image/avif",
            
            // Fonts
            "woff" => "font/woff",
            "woff2" => "font/woff2",
            "ttf" => "font/ttf",
            "otf" => "font/otf",
            "eot" => "application/vnd.ms-fontobject",
            
            // Media
            "mp3" => "audio/mpeg",
            "mp4" => "video/mp4",
            "webm" => "video/webm",
            "ogg" => "audio/ogg",
            "wav" => "audio/wav",
            
            // Archives
            "zip" => "application/zip",
            "tar" => "application/x-tar",
            "gz" => "application/gzip",
            
            // Documents
            "pdf" => "application/pdf",
            "doc" => "application/msword",
            "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            
            // WebAssembly
            "wasm" => "application/wasm",
            
            _ => &self.config.default_mime,
        }.to_string()
    }
    
    /// Generate ETag for a file
    fn generate_etag(&self, metadata: &Metadata, path: &Path) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        
        // Hash file size
        metadata.len().hash(&mut hasher);
        
        // Hash modification time
        if let Ok(modified) = metadata.modified() {
            if let Ok(duration) = modified.duration_since(SystemTime::UNIX_EPOCH) {
                duration.as_secs().hash(&mut hasher);
                duration.subsec_nanos().hash(&mut hasher);
            }
        }
        
        // Hash file path
        path.to_string_lossy().hash(&mut hasher);
        
        format!("{:x}", hasher.finish())
    }
    
    /// Get Last-Modified header value
    fn get_last_modified(&self, metadata: &Metadata) -> Option<String> {
        metadata.modified().ok()
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .and_then(|d| DateTime::<Utc>::from_timestamp(d.as_secs() as i64, 0))
            .map(|dt| dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string())
    }
}

/// Directory entry
#[derive(Debug)]
struct DirEntry {
    name: String,
    is_dir: bool,
    size: u64,
    modified: Option<u64>,
}

/// Parse Range header
fn parse_range(range: &str, file_size: u64) -> Option<(u64, u64)> {
    let range = range.strip_prefix("bytes=")?;
    let parts: Vec<&str> = range.split('-').collect();
    
    if parts.len() != 2 {
        return None;
    }
    
    // Handle suffix range: bytes=-500 means last 500 bytes
    if parts[0].is_empty() {
        let suffix: u64 = parts[1].parse().ok()?;
        let start = file_size.saturating_sub(suffix);
        return Some((start, file_size - 1));
    }
    
    let start: u64 = parts[0].parse().ok()?;
    
    let end: u64 = if parts[1].is_empty() {
        file_size - 1
    } else {
        parts[1].parse().ok()?
    };
    
    if start > end || start >= file_size {
        return None;
    }
    
    Some((start, end.min(file_size - 1)))
}

/// Format file size for display
fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    
    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// HTML escape
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;
    
    fn setup_test_dir() -> TempDir {
        let dir = TempDir::new().unwrap();
        
        // Create test files
        fs::write(dir.path().join("index.html"), "<html>Hello</html>").unwrap();
        fs::write(dir.path().join("style.css"), "body { }").unwrap();
        fs::write(dir.path().join("data.json"), "{}").unwrap();
        fs::write(dir.path().join("image.png"), &[0x89, 0x50, 0x4E, 0x47]).unwrap();
        fs::write(dir.path().join(".hidden"), "secret").unwrap();
        
        // Create subdirectory
        let subdir = dir.path().join("subdir");
        fs::create_dir(&subdir).unwrap();
        fs::write(subdir.join("nested.txt"), "nested content").unwrap();
        
        dir
    }
    
    #[test]
    fn test_file_server_creation() {
        let dir = setup_test_dir();
        let config = FileServerConfig::new(dir.path());
        let server = FileServer::new(config).unwrap();
        assert!(server.config.directory_listing);
    }
    
    #[test]
    fn test_serve_file() {
        let dir = setup_test_dir();
        let config = FileServerConfig::new(dir.path());
        let server = FileServer::new(config).unwrap();
        
        let resp = server.handle_request("GET", "/style.css", &HashMap::new());
        assert_eq!(resp.status, 200);
        assert!(resp.headers.get("Content-Type").unwrap().contains("text/css"));
    }
    
    #[test]
    fn test_serve_index() {
        let dir = setup_test_dir();
        let config = FileServerConfig::new(dir.path());
        let server = FileServer::new(config).unwrap();
        
        let resp = server.handle_request("GET", "/", &HashMap::new());
        assert_eq!(resp.status, 200);
        assert!(resp.headers.get("Content-Type").unwrap().contains("text/html"));
    }
    
    #[test]
    fn test_directory_listing() {
        let dir = setup_test_dir();
        let mut config = FileServerConfig::new(dir.path());
        config.index_files = vec![]; // Disable index files
        let server = FileServer::new(config).unwrap();
        
        let resp = server.handle_request("GET", "/", &HashMap::new());
        assert_eq!(resp.status, 200);
        let body = String::from_utf8_lossy(&resp.body);
        assert!(body.contains("subdir/"));
        assert!(body.contains("style.css"));
    }
    
    #[test]
    fn test_hidden_files() {
        let dir = setup_test_dir();
        let config = FileServerConfig::new(dir.path());
        let server = FileServer::new(config).unwrap();
        
        // Hidden files should not be accessible
        let resp = server.handle_request("GET", "/.hidden", &HashMap::new());
        assert_eq!(resp.status, 403);
    }
    
    #[test]
    fn test_path_traversal() {
        let dir = setup_test_dir();
        let config = FileServerConfig::new(dir.path());
        let server = FileServer::new(config).unwrap();
        
        let resp = server.handle_request("GET", "/../../../etc/passwd", &HashMap::new());
        assert!(resp.status == 403 || resp.status == 404);
    }
    
    #[test]
    fn test_not_found() {
        let dir = setup_test_dir();
        let config = FileServerConfig::new(dir.path());
        let server = FileServer::new(config).unwrap();
        
        let resp = server.handle_request("GET", "/nonexistent.txt", &HashMap::new());
        assert_eq!(resp.status, 404);
    }
    
    #[test]
    fn test_head_request() {
        let dir = setup_test_dir();
        let config = FileServerConfig::new(dir.path());
        let server = FileServer::new(config).unwrap();
        
        let resp = server.handle_request("HEAD", "/style.css", &HashMap::new());
        assert_eq!(resp.status, 200);
        assert!(resp.body.is_empty());
        assert!(resp.headers.contains_key("Content-Length"));
    }
    
    #[test]
    fn test_range_parsing() {
        assert_eq!(parse_range("bytes=0-499", 1000), Some((0, 499)));
        assert_eq!(parse_range("bytes=500-999", 1000), Some((500, 999)));
        assert_eq!(parse_range("bytes=-500", 1000), Some((500, 999)));
        assert_eq!(parse_range("bytes=500-", 1000), Some((500, 999)));
        assert_eq!(parse_range("bytes=1000-1500", 1000), None); // Out of range
    }
    
    #[test]
    fn test_mime_types() {
        let dir = setup_test_dir();
        let config = FileServerConfig::new(dir.path());
        let server = FileServer::new(config).unwrap();
        
        assert!(server.get_mime_type(Path::new("file.html")).contains("text/html"));
        assert!(server.get_mime_type(Path::new("file.css")).contains("text/css"));
        assert!(server.get_mime_type(Path::new("file.js")).contains("javascript"));
        assert!(server.get_mime_type(Path::new("file.png")).contains("image/png"));
        assert!(server.get_mime_type(Path::new("file.wasm")).contains("application/wasm"));
    }
    
    #[test]
    fn test_format_size() {
        assert_eq!(format_size(500), "500 B");
        assert_eq!(format_size(1024), "1.0 KB");
        assert_eq!(format_size(1536), "1.5 KB");
        assert_eq!(format_size(1048576), "1.0 MB");
        assert_eq!(format_size(1073741824), "1.0 GB");
    }
    
    #[test]
    fn test_etag_caching() {
        let dir = setup_test_dir();
        let config = FileServerConfig::new(dir.path());
        let server = FileServer::new(config).unwrap();
        
        // First request - get ETag
        let resp1 = server.handle_request("GET", "/style.css", &HashMap::new());
        assert_eq!(resp1.status, 200);
        let etag = resp1.headers.get("ETag").unwrap().clone();
        
        // Second request with If-None-Match
        let mut headers = HashMap::new();
        headers.insert("if-none-match".to_string(), etag);
        let resp2 = server.handle_request("GET", "/style.css", &headers);
        assert_eq!(resp2.status, 304);
    }
}
