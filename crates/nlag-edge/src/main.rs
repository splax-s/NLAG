//! NLAG Edge Server - Public ingress proxy
//!
//! The edge server is responsible for:
//! - Accepting agent connections
//! - Routing public traffic to appropriate agents
//! - TLS termination
//! - Rate limiting
//! - Connection lifecycle management

use std::process::ExitCode;

use clap::Parser;
use tracing::Level;
use tracing_subscriber::EnvFilter;

mod auth;
mod cli;
mod config;
mod domains;
mod loadbalancer;
mod logging;
mod metrics;
mod pool;
mod registry;
mod server;

use cli::Cli;

#[tokio::main]
async fn main() -> ExitCode {
    // Parse CLI arguments
    let cli = Cli::parse();

    // Initialize logging
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
        .with_thread_ids(true)
        .with_file(false)
        .json()
        .init();

    // Execute
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("Fatal error: {:#}", e);
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    use cli::Commands;
    
    // Handle subcommands
    match cli.command {
        Some(Commands::GenerateConfig) => {
            println!("{}", config::EdgeConfig::generate_sample_config());
            return Ok(());
        }
        Some(Commands::Run) | None => {
            // Continue with normal server startup
        }
    }
    
    let config = config::EdgeConfig::load(&cli.config)?;

    tracing::info!(
        "Starting NLAG Edge server v{}",
        env!("CARGO_PKG_VERSION")
    );
    tracing::info!("Agent listener: {}", config.agent_listen_addr);
    tracing::info!("Public listener: {}", config.public_listen_addr);
    tracing::info!("Metrics endpoint: {}", config.metrics_listen_addr);

    // Start metrics server in background
    let metrics_addr = config.metrics_listen_addr;
    tokio::spawn(async move {
        if let Err(e) = metrics::start_metrics_server(metrics_addr).await {
            tracing::error!("Metrics server error: {}", e);
        }
    });

    server::run_server(config).await
}
