//! CLI arguments for the edge server

use std::path::PathBuf;

use clap::Parser;

/// NLAG Edge Server - Public ingress proxy
#[derive(Parser, Debug)]
#[command(name = "nlag-edge")]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = "/etc/nlag/edge.toml")]
    pub config: PathBuf,

    /// Enable verbose output
    #[arg(short, long)]
    pub verbose: bool,
}
