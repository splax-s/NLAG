//! CLI argument definitions using clap
//!
//! This module defines all command-line arguments and subcommands
//! for the NLAG agent.

use clap::{Parser, Subcommand};

/// NLAG Agent - Expose local services through secure tunnels
#[derive(Parser, Debug)]
#[command(name = "nlag")]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Enable verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Disable TUI and use simple logging output
    #[arg(long, global = true)]
    pub no_tui: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Start tunnels from a configuration file
    #[command(alias = "s")]
    Start {
        /// Path to configuration file (YAML or TOML)
        #[arg(short, long)]
        config: Option<String>,

        /// Only start tunnels in this group
        #[arg(short, long)]
        group: Option<String>,

        /// Only start specific tunnel by name
        #[arg(short, long)]
        tunnel: Option<String>,

        /// Edge server address (overrides config)
        #[arg(short, long)]
        edge: Option<String>,

        /// Skip TLS verification (DANGEROUS - dev only)
        #[arg(short = 'k', long)]
        insecure: bool,

        /// Watch config file for changes and reload
        #[arg(short, long)]
        watch: bool,
    },

    /// Expose a local service through a secure tunnel
    #[command(alias = "e")]
    Expose {
        /// Protocol to use (tcp, http, https)
        #[arg(value_parser = parse_protocol)]
        protocol: nlag_common::Protocol,

        /// Local port to expose
        local_port: u16,

        /// Local host to forward to (default: 127.0.0.1)
        #[arg(short = 'H', long, default_value = "127.0.0.1")]
        local_host: String,

        /// Request a specific subdomain
        #[arg(short, long)]
        subdomain: Option<String>,

        /// Edge server address
        #[arg(short, long, default_value = "localhost:4443")]
        edge: String,

        /// Skip TLS verification (DANGEROUS - dev only)
        #[arg(short = 'k', long)]
        insecure: bool,

        /// Show request rate sparkline graph
        #[arg(long)]
        sparkline: bool,

        /// Show latency gauge visualization
        #[arg(long)]
        latency_gauge: bool,

        /// Show detailed request cards with more info
        #[arg(long)]
        request_details: bool,

        /// Show connection health indicator
        #[arg(long)]
        health: bool,
    },

    /// Expose multiple local services through a single tunnel connection
    #[command(alias = "m")]
    Multi {
        /// Services to expose in format: `protocol:local_port[:subdomain]`
        /// Example: http:8080:web tcp:5432:db
        #[arg(required = true, num_args = 1..)]
        services: Vec<String>,

        /// Local host to forward to (default: 127.0.0.1)
        #[arg(short = 'H', long, default_value = "127.0.0.1")]
        local_host: String,

        /// Edge server address
        #[arg(short, long, default_value = "localhost:4443")]
        edge: String,

        /// Skip TLS verification (DANGEROUS - dev only)
        #[arg(short = 'k', long)]
        insecure: bool,
    },

    /// Manage agent configuration
    #[command(alias = "cfg")]
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Authenticate with the NLAG control plane
    #[command(alias = "auth")]
    Login {
        /// Email address for authentication
        #[arg(short, long)]
        email: Option<String>,

        /// Control plane server address
        #[arg(short, long, default_value = "https://api.nlag.dev")]
        server: String,
    },

    /// Log out and clear stored credentials
    Logout,

    /// Show current authenticated user
    Whoami,

    /// Show the local request inspector
    #[command(alias = "i")]
    Inspect {
        /// Port for the inspector web interface
        #[arg(short, long, default_value = "4040")]
        port: u16,

        /// Bind address for the inspector
        #[arg(short, long, default_value = "127.0.0.1")]
        bind: String,
    },

    /// Show tunnel status and usage
    Status,

    /// Show version information
    Version,
}

#[derive(Subcommand, Debug)]
pub enum ConfigAction {
    /// Show current configuration
    Show,
    
    /// Initialize a new configuration file
    Init {
        /// Force overwrite existing config
        #[arg(short, long)]
        force: bool,
        
        /// Format of the config file (yaml or toml)
        #[arg(long, default_value = "yaml")]
        format: String,
    },
    
    /// Validate a configuration file
    Validate {
        /// Path to configuration file
        #[arg(short, long)]
        config: Option<String>,
    },
    
    /// Generate an example configuration file
    Example {
        /// Output format (yaml or toml)
        #[arg(long, default_value = "yaml")]
        format: String,
    },
    
    /// Show the configuration file path
    Path,
}

/// Parsed service specification for multi-expose
#[derive(Debug, Clone)]
pub struct ServiceSpec {
    pub protocol: nlag_common::Protocol,
    pub local_port: u16,
    pub subdomain: Option<String>,
}

impl ServiceSpec {
    /// Parse a service specification string
    /// Format: `protocol:port[:subdomain]`
    pub fn parse(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.split(':').collect();
        
        if parts.len() < 2 || parts.len() > 3 {
            return Err(format!(
                "Invalid service spec '{}'. Expected format: protocol:port[:subdomain]",
                s
            ));
        }

        let protocol: nlag_common::Protocol = parts[0].parse()?;
        let local_port: u16 = parts[1]
            .parse()
            .map_err(|_| format!("Invalid port number: {}", parts[1]))?;
        
        let subdomain = if parts.len() == 3 {
            Some(parts[2].to_string())
        } else {
            None
        };

        Ok(Self {
            protocol,
            local_port,
            subdomain,
        })
    }
}

fn parse_protocol(s: &str) -> Result<nlag_common::Protocol, String> {
    s.parse()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parsing() {
        let cli = Cli::parse_from(["nlag", "expose", "http", "8080"]);
        match cli.command {
            Commands::Expose {
                protocol,
                local_port,
                ..
            } => {
                assert_eq!(protocol, nlag_common::Protocol::Http);
                assert_eq!(local_port, 8080);
            }
            _ => panic!("Wrong command"),
        }
    }

    #[test]
    fn test_expose_with_options() {
        let cli = Cli::parse_from([
            "nlag",
            "expose",
            "tcp",
            "3000",
            "--local-host",
            "localhost",
            "--subdomain",
            "myapp",
        ]);

        match cli.command {
            Commands::Expose {
                local_host,
                subdomain,
                ..
            } => {
                assert_eq!(local_host, "localhost");
                assert_eq!(subdomain, Some("myapp".to_string()));
            }
            _ => panic!("Wrong command"),
        }
    }
}
