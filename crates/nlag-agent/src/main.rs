//! NLAG Agent - CLI client for exposing local services
//!
//! The agent is responsible for:
//! - Establishing secure tunnels to edge servers
//! - Forwarding traffic to local services
//! - Managing connection lifecycle
//! - Automatic reconnection on failure

use std::process::ExitCode;

use clap::Parser;
use tracing::Level;
use tracing_subscriber::EnvFilter;

mod cli;
mod config;
mod tunnel;
mod ui;

use cli::{Cli, Commands, ServiceSpec};

#[tokio::main]
async fn main() -> ExitCode {
    // Parse CLI arguments
    let cli = Cli::parse();

    // Only initialize logging if TUI is disabled
    if cli.no_tui {
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            let level = if cli.verbose {
                Level::DEBUG
            } else {
                Level::INFO
            };
            EnvFilter::new(format!("nlag={},nlag_common={}", level, level))
        });

        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(true)
            .with_thread_ids(false)
            .with_file(false)
            .init();
    }

    // Execute command
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            if !std::env::var("NLAG_TUI_ACTIVE").is_ok() {
                eprintln!("Error: {:#}", e);
            }
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let use_tui = !cli.no_tui;

    match cli.command {
        Commands::Expose {
            protocol,
            local_port,
            local_host,
            subdomain,
            edge,
            insecure,
        } => {
            let mut config = config::AgentConfig::load()?;
            
            // Override with CLI args
            config.edge_addr = edge.clone();
            if insecure {
                config.tls.insecure_skip_verify = true;
            }
            
            let tunnel_config = config::TunnelOptions {
                protocol,
                local_port,
                local_host: local_host.clone(),
                subdomain,
            };

            if use_tui {
                tunnel::run_tunnel_with_ui(config, tunnel_config).await
            } else {
                tunnel::run_tunnel(config, tunnel_config).await
            }
        }

        Commands::Multi {
            services,
            local_host,
            edge,
            insecure,
        } => {
            // Parse all service specs
            let specs: Vec<ServiceSpec> = services
                .iter()
                .map(|s| ServiceSpec::parse(s))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| anyhow::anyhow!("{}", e))?;

            if specs.is_empty() {
                return Err(anyhow::anyhow!("At least one service must be specified"));
            }

            let mut config = config::AgentConfig::load()?;
            config.edge_addr = edge;
            if insecure {
                config.tls.insecure_skip_verify = true;
            }

            // Convert specs to tunnel options
            let tunnel_configs: Vec<config::TunnelOptions> = specs
                .into_iter()
                .map(|spec| config::TunnelOptions {
                    protocol: spec.protocol,
                    local_port: spec.local_port,
                    local_host: local_host.clone(),
                    subdomain: spec.subdomain,
                })
                .collect();

            tunnel::run_multi_tunnel(config, tunnel_configs).await
        }

        Commands::Config { action } => {
            use cli::ConfigAction;
            
            match action {
                ConfigAction::Show => {
                    let config = config::AgentConfig::load()?;
                    println!("{}", serde_json::to_string_pretty(&config)?);
                }
                ConfigAction::Init { force } => {
                    let path = config::AgentConfig::config_path()?;
                    if path.exists() && !force {
                        anyhow::bail!(
                            "Configuration file already exists at {}. Use --force to overwrite.",
                            path.display()
                        );
                    }
                    let created_path = config::AgentConfig::create_default_config()?;
                    println!("Created configuration file at: {}", created_path.display());
                }
                ConfigAction::Path => {
                    let path = config::AgentConfig::config_path()?;
                    println!("{}", path.display());
                }
            }
            Ok(())
        }

        Commands::Version => {
            println!("nlag {}", env!("CARGO_PKG_VERSION"));
            println!("Protocol version: {}", nlag_common::protocol::CURRENT_PROTOCOL_VERSION);
            Ok(())
        }
    }
}
