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

mod agent_config;
mod auth;
mod cli;
mod config;
mod file_server;
mod inspect;
mod tunnel;
mod ui;

use cli::{Cli, Commands, ConfigAction, ServiceSpec};

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
            if std::env::var("NLAG_TUI_ACTIVE").is_err() {
                eprintln!("Error: {:#}", e);
            }
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let use_tui = !cli.no_tui;

    match cli.command {
        Commands::Start {
            config,
            group,
            tunnel,
            edge,
            insecure,
            watch,
        } => {
            // Require authentication before creating tunnels
            if !auth::is_authenticated() {
                return Err(anyhow::anyhow!(
                    "You must be logged in to create tunnels.\n\n\
                     Run `nlag login` to authenticate, or create an account at your control plane's dashboard.\n\
                     Example: nlag login"
                ));
            }
            
            handle_start(config, group, tunnel, edge, insecure, watch, use_tui).await
        }

        Commands::Expose {
            protocol,
            local_port,
            local_host,
            subdomain,
            edge,
            insecure,
            sparkline,
            latency_gauge,
            request_details,
            health,
        } => {
            // Require authentication before creating tunnels
            if !auth::is_authenticated() {
                return Err(anyhow::anyhow!(
                    "You must be logged in to create tunnels.\n\n\
                     Run `nlag login` to authenticate, or create an account at your control plane's dashboard.\n\
                     Example: nlag login"
                ));
            }
            
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
            
            // Build widget config from CLI flags
            let widget_config = ui::WidgetConfig {
                sparkline,
                latency_gauge,
                request_details,
                health_indicator: health,
            };

            if use_tui {
                tunnel::run_tunnel_with_ui(config, tunnel_config, widget_config).await
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
            // Require authentication before creating tunnels
            if !auth::is_authenticated() {
                return Err(anyhow::anyhow!(
                    "You must be logged in to create tunnels.\n\n\
                     Run `nlag login` to authenticate, or create an account at your control plane's dashboard.\n\
                     Example: nlag login"
                ));
            }
            
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
            match action {
                ConfigAction::Show => {
                    let config = config::AgentConfig::load()?;
                    println!("{}", serde_json::to_string_pretty(&config)?);
                }
                ConfigAction::Init { force, format } => {
                    let path = config::AgentConfig::config_path()?;
                    
                    // Determine file extension based on format
                    let path = if format == "toml" {
                        path.with_extension("toml")
                    } else {
                        path.with_extension("yaml")
                    };
                    
                    if path.exists() && !force {
                        anyhow::bail!(
                            "Configuration file already exists at {}. Use --force to overwrite.",
                            path.display()
                        );
                    }
                    let created_path = config::AgentConfig::create_default_config()?;
                    println!("Created configuration file at: {}", created_path.display());
                }
                ConfigAction::Validate { config: config_path } => {
                    let path = match config_path {
                        Some(p) => std::path::PathBuf::from(p),
                        None => agent_config::AgentConfig::default_config_path()?,
                    };
                    
                    match agent_config::AgentConfig::load(&path) {
                        Ok(cfg) => {
                            if let Err(e) = cfg.validate() {
                                anyhow::bail!("Configuration validation failed:\n{}", e);
                            }
                            println!("✓ Configuration is valid");
                            println!("  Tunnels: {}", cfg.tunnels.len());
                            println!("  Groups: {}", cfg.groups.len());
                        }
                        Err(e) => {
                            anyhow::bail!("Failed to parse configuration: {}", e);
                        }
                    }
                }
                ConfigAction::Example { format } => {
                    let example = agent_config::AgentConfig::example_config(&format);
                    println!("{}", example);
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

        Commands::Completions { shell } => {
            cli::generate_completions(shell);
            Ok(())
        }

        Commands::Login { email, password, server } => {
            handle_login(email, password, server).await
        }

        Commands::Logout => {
            handle_logout()
        }

        Commands::Whoami => {
            handle_whoami()
        }

        Commands::Inspect { port, bind } => {
            handle_inspect(port, bind).await
        }

        Commands::Status => {
            handle_status().await
        }
    }
}

/// Handle the login command
async fn handle_login(email: Option<String>, password: Option<String>, server: String) -> anyhow::Result<()> {
    use std::io::{self, Write};
    
    // Get email from arg or prompt
    let email = match email {
        Some(e) => e,
        None => {
            print!("Email: ");
            io::stdout().flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            input.trim().to_string()
        }
    };
    
    if email.is_empty() {
        anyhow::bail!("Email is required");
    }
    
    // Get password from arg, env, or prompt
    let password = match password {
        Some(p) => p,
        None => rpassword::prompt_password("Password: ")?,
    };
    
    if password.is_empty() {
        anyhow::bail!("Password is required");
    }
    
    println!("Authenticating with {}...", server);
    
    match auth::login(&server, &email, &password).await {
        Ok(creds) => {
            println!();
            println!("✓ Successfully authenticated as {}", creds.email);
            println!("  Tier: {} ({} tunnel(s) max)", creds.tier, creds.max_tunnels);
            Ok(())
        }
        Err(e) => {
            anyhow::bail!("Login failed: {}", e);
        }
    }
}

/// Handle the logout command
fn handle_logout() -> anyhow::Result<()> {
    match auth::load_credentials() {
        Ok(creds) => {
            auth::clear_credentials()?;
            println!("✓ Logged out from {} ({})", creds.email, creds.server);
        }
        Err(_) => {
            println!("Not currently logged in.");
        }
    }
    Ok(())
}

/// Handle the whoami command
fn handle_whoami() -> anyhow::Result<()> {
    match auth::load_credentials() {
        Ok(creds) => {
            println!("Email:       {}", creds.email);
            println!("Server:      {}", creds.server);
            println!("Tier:        {}", creds.tier);
            println!("Max Tunnels: {}", creds.max_tunnels);
            
            // Check token expiration
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            
            let remaining = creds.expires_at.saturating_sub(now);
            if remaining > 0 {
                let hours = remaining / 3600;
                let minutes = (remaining % 3600) / 60;
                println!("Session:     {} hours {} minutes remaining", hours, minutes);
            } else {
                println!("Session:     Expired");
            }
        }
        Err(_) => {
            println!("Not logged in. Run `nlag login` to authenticate.");
        }
    }
    Ok(())
}

/// Handle the inspect command - run local traffic inspector
async fn handle_inspect(port: u16, bind: String) -> anyhow::Result<()> {
    println!("Starting NLAG Inspector on http://{}:{}", bind, port);
    println!("Press Ctrl+C to stop");
    println!();
    
    // Create inspector instance
    let inspector = inspect::LocalInspector::new();
    
    // Configure sync if authenticated
    if let Ok(creds) = auth::load_credentials() {
        inspector.configure_sync(creds.server, creds.access_token);
        println!("✓ Traffic will sync to dashboard");
    } else {
        println!("ℹ Login with `nlag login` to sync traffic to dashboard");
    }
    
    println!();
    println!("Inspector UI: http://{}:{}", bind, port);
    
    // Run the inspect server
    inspect::run_inspect_server(inspector, &bind, port).await
}

/// Handle the status command
async fn handle_status() -> anyhow::Result<()> {
    // Check if logged in
    match auth::load_credentials() {
        Ok(creds) => {
            println!("Account:  {} ({})", creds.email, creds.tier);
            println!("Server:   {}", creds.server);
            
            // Try to get tunnel count from server
            match auth::get_tunnel_count(&creds).await {
                Ok(count) => {
                    println!("Tunnels:  {}/{}", count, creds.max_tunnels);
                }
                Err(_) => {
                    println!("Tunnels:  (unable to fetch)");
                }
            }
        }
        Err(_) => {
            println!("Not logged in.");
            println!();
            println!("Run `nlag login` to authenticate and enable:");
            println!("  • Traffic inspection in dashboard");
            println!("  • Tunnel history and analytics");
            println!("  • Custom domains (Pro tier)");
        }
    }
    
    Ok(())
}

/// Handle the start command - load tunnels from config file
#[allow(clippy::too_many_arguments)]
async fn handle_start(
    config_path: Option<String>,
    group_filter: Option<String>,
    tunnel_filter: Option<String>,
    edge_override: Option<String>,
    insecure: bool,
    watch: bool,
    use_tui: bool,
) -> anyhow::Result<()> {
    use std::path::PathBuf;
    
    // Find config file
    let path = match config_path {
        Some(p) => PathBuf::from(p),
        None => agent_config::AgentConfig::default_config_path()?,
    };
    
    if !path.exists() {
        anyhow::bail!(
            "Configuration file not found: {}\n\n\
             Create one with: nlag config init\n\
             Or specify a path with: nlag start --config <path>",
            path.display()
        );
    }
    
    println!("Loading configuration from: {}", path.display());
    
    // Load and validate config
    let agent_cfg = agent_config::AgentConfig::load(&path)?;
    agent_cfg.validate()?;
    
    // Get tunnels to start (filtered by group/name)
    let tunnels = agent_cfg.get_tunnels_to_start(group_filter.as_deref(), tunnel_filter.as_deref());
    
    if tunnels.is_empty() {
        if group_filter.is_some() || tunnel_filter.is_some() {
            anyhow::bail!("No tunnels matched the specified filters");
        } else {
            anyhow::bail!("No tunnels defined in configuration file");
        }
    }
    
    println!("Starting {} tunnel(s)...", tunnels.len());
    for t in &tunnels {
        println!("  • {} ({}) -> {}:{}", 
            t.name.as_deref().unwrap_or("unnamed"),
            t.protocol.as_deref().unwrap_or("http"),
            t.local_host.as_deref().unwrap_or("127.0.0.1"),
            t.local_port
        );
    }
    println!();
    
    // Convert to tunnel options
    let mut base_config = config::AgentConfig::load()?;
    
    // Apply overrides
    if let Some(ref edge) = edge_override {
        base_config.edge_addr = edge.clone();
    } else if let Some(ref edge) = agent_cfg.edge_url {
        base_config.edge_addr = edge.clone();
    }
    
    if insecure {
        base_config.tls.insecure_skip_verify = true;
    }
    
    // Convert TunnelConfig to TunnelOptions
    let tunnel_options: Vec<config::TunnelOptions> = tunnels
        .into_iter()
        .map(|t| {
            let protocol = t.protocol
                .as_deref()
                .unwrap_or("http")
                .parse()
                .unwrap_or(nlag_common::Protocol::Http);
            
            config::TunnelOptions {
                protocol,
                local_port: t.local_port,
                local_host: t.local_host.clone().unwrap_or_else(|| "127.0.0.1".to_string()),
                subdomain: t.subdomain.clone(),
            }
        })
        .collect();
    
    if watch {
        println!("Watching configuration file for changes...");
        // TODO: Implement file watching with notify crate
    }
    
    // Run multi-tunnel
    if tunnel_options.len() == 1 && use_tui {
        let tunnel_cfg = tunnel_options.into_iter().next().unwrap();
        let widget_config = ui::WidgetConfig::default();
        tunnel::run_tunnel_with_ui(base_config, tunnel_cfg, widget_config).await
    } else {
        tunnel::run_multi_tunnel(base_config, tunnel_options).await
    }
}
