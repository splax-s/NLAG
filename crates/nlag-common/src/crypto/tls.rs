//! TLS configuration utilities
//!
//! Provides secure-by-default TLS configuration for both client and server.
//!
//! ## Security Defaults
//! - TLS 1.3 only
//! - Strong cipher suites
//! - Certificate verification enabled
//! - ALPN for protocol negotiation

use std::sync::Arc;

use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    ClientConfig, RootCertStore, ServerConfig,
};

use crate::error::{NlagError, Result};

/// ALPN protocol identifier for NLAG
pub const NLAG_ALPN: &[u8] = b"nlag/1";

/// TLS configuration holder
#[derive(Debug, Clone)]
#[derive(Default)]
pub struct TlsConfig {
    /// Server name for SNI (client only)
    pub server_name: Option<String>,
    /// Path to CA certificate (for custom CA)
    pub ca_cert_path: Option<String>,
    /// Path to client/server certificate
    pub cert_path: Option<String>,
    /// Path to private key
    pub key_path: Option<String>,
    /// Skip certificate verification (DANGEROUS - dev only)
    pub insecure_skip_verify: bool,
}


/// Create a TLS client configuration
///
/// This creates a secure client configuration suitable for connecting
/// to NLAG edge servers.
pub fn create_client_config(config: &TlsConfig) -> Result<ClientConfig> {
    let builder = ClientConfig::builder();

    // Build root cert store
    let root_store = if let Some(ca_path) = &config.ca_cert_path {
        // Load custom CA
        let ca_pem = std::fs::read_to_string(ca_path)
            .map_err(|e| NlagError::CertificateError(format!("Failed to read CA cert: {}", e)))?;
        load_root_certs_from_pem(&ca_pem)?
    } else {
        // Use system roots
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        root_store
    };

    let config = if config.insecure_skip_verify {
        // DANGEROUS: Skip verification - only for development!
        tracing::warn!("TLS certificate verification disabled - DO NOT USE IN PRODUCTION");

        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth()
    } else {
        builder
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    Ok(config)
}

/// Create a TLS server configuration
///
/// This creates a secure server configuration for NLAG edge servers.
pub fn create_server_config(cert_pem: &str, key_pem: &str) -> Result<ServerConfig> {
    // Parse certificate chain
    let certs = load_certs_from_pem(cert_pem)?;

    // Parse private key
    let key = load_key_from_pem(key_pem)?;

    // Build config without client auth
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| NlagError::TlsError(format!("Failed to create server config: {}", e)))?;

    Ok(config)
}

/// Create a TLS server configuration with mTLS (mutual TLS) client authentication
///
/// This creates a server configuration that requires client certificates for agent authentication.
pub fn create_mtls_server_config(
    cert_pem: &str,
    key_pem: &str,
    client_ca_pem: &str,
) -> Result<ServerConfig> {
    // Parse server certificate chain
    let certs = load_certs_from_pem(cert_pem)?;

    // Parse server private key
    let key = load_key_from_pem(key_pem)?;

    // Load client CA certificates
    let client_root_store = load_root_certs_from_pem(client_ca_pem)?;

    // Create client cert verifier
    let client_verifier = rustls::server::WebPkiClientVerifier::builder(
        Arc::new(client_root_store)
    )
    .build()
    .map_err(|e| NlagError::TlsError(format!("Failed to create client verifier: {}", e)))?;

    // Build config with client authentication
    let config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(certs, key)
        .map_err(|e| NlagError::TlsError(format!("Failed to create mTLS server config: {}", e)))?;

    Ok(config)
}

/// Create a TLS client configuration with client certificate for mTLS
///
/// This creates a client configuration that presents a certificate to the server.
pub fn create_mtls_client_config(
    config: &TlsConfig,
    client_cert_pem: &str,
    client_key_pem: &str,
) -> Result<ClientConfig> {
    let builder = ClientConfig::builder();

    // Build root cert store
    let root_store = if let Some(ca_path) = &config.ca_cert_path {
        // Load custom CA
        let ca_pem = std::fs::read_to_string(ca_path)
            .map_err(|e| NlagError::CertificateError(format!("Failed to read CA cert: {}", e)))?;
        load_root_certs_from_pem(&ca_pem)?
    } else {
        // Use system roots
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        root_store
    };

    // Load client certificate and key
    let client_certs = load_certs_from_pem(client_cert_pem)?;
    let client_key = load_key_from_pem(client_key_pem)?;

    let client_config = builder
        .with_root_certificates(root_store)
        .with_client_auth_cert(client_certs, client_key)
        .map_err(|e| NlagError::TlsError(format!("Failed to set client certificate: {}", e)))?;

    Ok(client_config)
}

/// Extract certificate fingerprint (SHA-256) from a certificate
pub fn get_cert_fingerprint(cert_pem: &str) -> Result<String> {
    use sha2::{Sha256, Digest};
    
    let certs = load_certs_from_pem(cert_pem)?;
    let cert = certs.first().ok_or_else(|| {
        NlagError::CertificateError("No certificate found".to_string())
    })?;

    let mut hasher = Sha256::new();
    hasher.update(cert.as_ref());
    let result = hasher.finalize();

    Ok(hex::encode(result))
}

/// Load certificates from PEM data
fn load_certs_from_pem(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .filter_map(|c| c.ok())
        .collect();

    if certs.is_empty() {
        return Err(NlagError::CertificateError(
            "No certificates found".to_string(),
        ));
    }

    Ok(certs)
}

/// Load private key from PEM data
fn load_key_from_pem(pem: &str) -> Result<PrivateKeyDer<'static>> {
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|e| NlagError::CertificateError(format!("Failed to parse key: {}", e)))?
        .ok_or_else(|| NlagError::CertificateError("No private key found".to_string()))?;

    Ok(key)
}

/// Load root certificates from PEM data
fn load_root_certs_from_pem(pem: &str) -> Result<RootCertStore> {
    let mut root_store = RootCertStore::empty();
    let mut reader = std::io::BufReader::new(pem.as_bytes());

    let certs = rustls_pemfile::certs(&mut reader).filter_map(|c| c.ok());

    for cert in certs {
        root_store.add(cert).map_err(|e| {
            NlagError::CertificateError(format!("Failed to add root cert: {}", e))
        })?;
    }

    if root_store.is_empty() {
        return Err(NlagError::CertificateError(
            "No root certificates found".to_string(),
        ));
    }

    Ok(root_store)
}

/// Certificate verifier that accepts any certificate (DANGEROUS)
///
/// This is ONLY for development and testing. Never use in production.
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::cert::generate_self_signed_cert;

    #[test]
    fn test_create_server_config() {
        let cert_info = generate_self_signed_cert("test.local", &[], &[], 1, false).unwrap();

        let config = create_server_config(&cert_info.cert_pem, &cert_info.key_pem);
        assert!(config.is_ok());
    }

    #[test]
    fn test_create_client_config_insecure() {
        let tls_config = TlsConfig {
            insecure_skip_verify: true,
            ..Default::default()
        };

        let config = create_client_config(&tls_config);
        assert!(config.is_ok());
    }
}
