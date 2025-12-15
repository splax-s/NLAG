//! CLI arguments for the edge server

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// NLAG Edge Server - Public ingress proxy
#[derive(Parser, Debug)]
#[command(name = "nlag-edge")]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
    
    /// Path to configuration file
    #[arg(short, long, default_value = "/etc/nlag/edge.toml", global = true)]
    pub config: PathBuf,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run the edge server (default)
    Run,
    
    /// Generate a sample configuration file
    GenerateConfig,
}
