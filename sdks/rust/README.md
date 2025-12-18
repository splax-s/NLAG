# NLAG Rust SDK

Official Rust SDK for NLAG - expose local services through secure tunnels.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
nlag-sdk = "0.1"
tokio = { version = "1", features = ["full"] }
```

## Quick Start

```rust
use nlag_sdk::{Client, TunnelConfig, Protocol};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Create a client (uses stored credentials)
    let client = Client::new().await?;

    // Expose port 8080 with HTTP
    let tunnel = client.expose(TunnelConfig {
        protocol: Protocol::Http,
        local_port: 8080,
        subdomain: Some("my-app".to_string()),
        ..Default::default()
    }).await?;

    println!("Tunnel URL: {}", tunnel.public_url());

    // Wait for Ctrl+C
    tokio::signal::ctrl_c().await?;
    tunnel.close().await?;

    Ok(())
}
```

## Authentication

### Login with Email/Password

```rust
use nlag_sdk::auth;

let credentials = auth::authenticate(
    "https://api.nlag.dev",
    "user@example.com",
    "password"
).await?;
```

### Login with API Token

```rust
use nlag_sdk::auth;

let credentials = auth::authenticate_with_token(
    "https://api.nlag.dev",
    "nlag_xxxxxxxxxxxx"
).await?;
```

### Load Stored Credentials

```rust
use nlag_sdk::auth;

let credentials = auth::load_credentials().await?;
```

## Client Configuration

```rust
use nlag_sdk::{Client, ClientConfig};

let client = Client::with_config(ClientConfig {
    api_url: "https://api.nlag.dev".to_string(),
    edge_url: "wss://connect.nlag.dev".to_string(),
    region: Some("us-west".to_string()),
    timeout_secs: 30,
    auto_reconnect: true,
    max_retries: 5,
    verify_tls: true,
    ..Default::default()
}).await?;
```

## Tunnel Configuration

```rust
use nlag_sdk::{TunnelConfig, Protocol};
use std::collections::HashMap;

let config = TunnelConfig {
    protocol: Protocol::Http,
    local_host: "127.0.0.1".to_string(),
    local_port: 3000,
    subdomain: Some("api".to_string()),
    
    // Basic auth
    basic_auth: Some(HashMap::from([
        ("admin".to_string(), "secret".to_string()),
    ])),
    
    // IP restrictions
    ip_allow: Some(vec!["10.0.0.0/8".to_string()]),
    ip_deny: Some(vec!["192.168.1.100".to_string()]),
    
    // Custom headers
    headers: Some(HashMap::from([
        ("X-Custom".to_string(), "value".to_string()),
    ])),
    
    // Enable request inspection
    inspect: true,
    
    ..Default::default()
};
```

## Working with Tunnels

### Create a Tunnel

```rust
let tunnel = client.expose(TunnelConfig {
    local_port: 8080,
    ..Default::default()
}).await?;

println!("ID: {}", tunnel.id());
println!("URL: {}", tunnel.public_url());
println!("State: {:?}", tunnel.state());
```

### List Tunnels

```rust
let tunnels = client.list_tunnels().await?;
for tunnel in tunnels {
    println!("{}: {} -> {}", tunnel.id, tunnel.public_url, tunnel.local_address);
}
```

### Get Tunnel Info

```rust
let info = client.get_tunnel("tunnel-id").await?;
println!("Requests: {}", info.metrics.requests_total);
```

### Close Tunnel

```rust
// Close specific tunnel
tunnel.close().await?;

// Or by ID
client.close_tunnel("tunnel-id").await?;

// Close all tunnels
client.close_all().await?;
```

## Protocols

| Protocol | Description |
|----------|-------------|
| `Protocol::Http` | HTTP traffic |
| `Protocol::Https` | HTTPS with TLS termination |
| `Protocol::Tcp` | Raw TCP connections |
| `Protocol::Udp` | UDP datagrams |
| `Protocol::Grpc` | gRPC traffic |
| `Protocol::WebSocket` | WebSocket connections |

## Error Handling

```rust
use nlag_sdk::Error;

match client.expose(config).await {
    Ok(tunnel) => println!("Created: {}", tunnel.public_url()),
    Err(Error::Authentication(msg)) => eprintln!("Auth error: {}", msg),
    Err(Error::RateLimit) => eprintln!("Rate limited, try again later"),
    Err(Error::QuotaExceeded(msg)) => eprintln!("Quota exceeded: {}", msg),
    Err(e) => eprintln!("Error: {}", e),
}
```

## Async Runtime

The SDK uses [tokio](https://tokio.rs/) for async operations:

```toml
[dependencies]
nlag-sdk = "0.1"
tokio = { version = "1", features = ["full"] }
```

## Examples

### HTTP Server with Tunnel

```rust
use nlag_sdk::{Client, TunnelConfig, Protocol};
use axum::{routing::get, Router};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Start local server
    let app = Router::new().route("/", get(|| async { "Hello!" }));
    
    tokio::spawn(async {
        axum::serve(
            tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap(),
            app
        ).await.unwrap();
    });

    // Create tunnel
    let client = Client::new().await?;
    let tunnel = client.expose(TunnelConfig {
        protocol: Protocol::Http,
        local_port: 3000,
        ..Default::default()
    }).await?;

    println!("Server available at: {}", tunnel.public_url());
    
    tokio::signal::ctrl_c().await?;
    Ok(())
}
```

### Multiple Tunnels

```rust
let client = Client::new().await?;

let http_tunnel = client.expose(TunnelConfig {
    protocol: Protocol::Http,
    local_port: 8080,
    subdomain: Some("web".to_string()),
    ..Default::default()
}).await?;

let grpc_tunnel = client.expose(TunnelConfig {
    protocol: Protocol::Grpc,
    local_port: 50051,
    subdomain: Some("api".to_string()),
    ..Default::default()
}).await?;

println!("Web: {}", http_tunnel.public_url());
println!("API: {}", grpc_tunnel.public_url());
```

## License

MIT
