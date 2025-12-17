# NLAG - Next-Generation Low-Latency Access Gateway

A production-grade secure tunneling platform built in Rust, providing:

- Zero-trust security with mTLS & JWT authentication
- Low-latency QUIC transport
- High concurrency through stream multiplexing
- Enterprise-ready features: Rate limiting, Load balancing, Custom domains
- Real-time request inspection (ngrok-style)
- Modern dashboard UI

## Features

### ✅ Core Features

- **QUIC Transport**: Ultra-low latency multiplexed connections
- **HTTP/HTTPS Tunneling**: Full HTTP/1.1 and HTTP/2 support
- **WebSocket Tunneling**: Seamless WebSocket pass-through
- **TCP Tunneling**: Raw TCP port forwarding
- **TLS Termination**: Automatic TLS with Let's Encrypt (planned) or custom certs

### ✅ Enterprise Features

- **JWT Authentication**: Secure agent authentication with RS256/HS256
- **Rate Limiting**: Per-tunnel request rate limiting with token bucket
- **Load Balancing**: Multiple strategies (Round Robin, Least Connections, IP Hash, etc.)
- **Connection Pooling**: Efficient connection reuse
- **Custom Domains**: CNAME/TXT verification for custom domain mapping
- **Graceful Shutdown**: Proper connection draining

### ✅ Observability

- **Prometheus Metrics**: Full metrics export for monitoring
- **Request Inspection**: Live HTTP request/response viewer (ngrok-style)
- **Structured Logging**: JSON logs for aggregation

### ✅ Developer Experience

- **Terminal UI**: Beautiful TUI showing tunnel status and requests
- **Dashboard**: Web-based management interface
- **Docker Support**: Full Docker and docker-compose setup
- **Warning Page**: Security interstitial for first-time browser visits

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          NLAG Architecture                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────┐         ┌─────────────┐         ┌─────────────┐  │
│  │   Public    │  HTTP   │    Edge     │  QUIC   │    Agent    │  │
│  │   Client    │────────►│   Server    │◄───────►│   (Local)   │  │
│  └─────────────┘         └──────┬──────┘         └──────┬──────┘  │
│                                 │                       │          │
│                                 │                       │          │
│                          ┌──────▼──────┐         ┌──────▼──────┐  │
│                          │   Control   │         │   Local     │  │
│                          │   Plane     │         │   Service   │  │
│                          └─────────────┘         └─────────────┘  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## Crates

| Crate | Description |
|-------|-------------|
| `nlag-agent` | CLI client for exposing local services |
| `nlag-edge` | Public ingress/proxy server |
| `nlag-control` | Control plane (auth, management) |
| `nlag-common` | Shared protocol, crypto, types |

## Quick Start

### Prerequisites

- Rust 1.75+ (stable)
- Linux or macOS

### Building

```bash
# Build all crates
cargo build --release

# Build specific crate
cargo build -p nlag-agent --release
```

### Running the Edge Server

```bash
# Development mode (auto-generates certificates)
cargo run -p nlag-edge

# Production mode (with config file)
cargo run -p nlag-edge -- --config /etc/nlag/edge.toml

# Generate sample configuration
cargo run -p nlag-edge -- generate-config
```

### Running the Control Plane

```bash
# Start the dashboard and API server
cargo run -p nlag-control

# Access the dashboard at http://localhost:3000
```

### Request Inspection

When the edge server is running, access the inspect UI at:

- `http://localhost:4040/inspect/ui` - Main inspector interface
- `http://localhost:4040/inspect/ui/{tunnel_id}` - Tunnel-specific view
- `http://localhost:4040/health` - Health check endpoint

### Exposing a Local Service

```bash
# Expose HTTP service on port 8080
cargo run -p nlag-agent -- expose http 8080

# Expose with custom subdomain
cargo run -p nlag-agent -- expose http 8080 --subdomain myapp

# Expose TCP service
cargo run -p nlag-agent -- expose tcp 3000
```

## CLI Usage

### Agent Commands

```bash
# Expose a local service
nlag expose <protocol> <local_port> [options]

Options:
  -H, --local-host <HOST>   Local host to forward to (default: 127.0.0.1)
  -s, --subdomain <NAME>    Request specific subdomain
  -v, --verbose             Enable verbose output

# Show configuration
nlag config --show

# Show version
nlag version
```

### Examples

```bash
# Expose local web server
nlag expose http 3000

# Expose with verbose logging
nlag -v expose http 8080

# Expose to specific local host
nlag expose http 8080 --local-host localhost

# Request specific subdomain
nlag expose http 8080 --subdomain my-app
```

## Configuration

### Agent Configuration

The agent reads configuration from `~/.nlag/config.toml`:

```toml
# Edge server address
edge_addr = "edge.example.com:4443"

# Authentication token
auth_token = "your-token-here"

[tls]
# Skip TLS verification (development only!)
insecure_skip_verify = false

# Custom CA certificate
# ca_cert = "/path/to/ca.pem"

[connection]
reconnect_delay_ms = 1000
max_reconnect_delay_ms = 30000
max_reconnect_attempts = 0  # 0 = infinite
connect_timeout_secs = 30
```

### Edge Configuration

The edge server reads configuration from `/etc/nlag/edge.toml`:

```toml
agent_listen_addr = "0.0.0.0:4443"
public_listen_addr = "0.0.0.0:8080"
metrics_listen_addr = "0.0.0.0:9090"
inspect_listen_addr = "0.0.0.0:4040"

[tls]
cert_path = "/etc/nlag/certs/edge.crt"
key_path = "/etc/nlag/certs/edge.key"

[domain]
base_domain = "tunnels.example.com"
scheme = "https"

[rate_limit]
requests_per_second = 1000
burst_size = 100
max_connections_per_tunnel = 100

[auth]
enabled = true
algorithm = "RS256"
jwt_public_key = "/etc/nlag/jwt-public.pem"

[inspect]
enabled = true
max_body_size = 1048576  # 1MB
max_requests_per_tunnel = 500

[warning]
enabled = true
title = "Security Warning"
message = "You are about to access a tunnel..."
bypass_hosts = ["internal.example.com"]

[load_balancer]
strategy = "round_robin"  # round_robin, least_connections, random, ip_hash
health_check_interval_secs = 30
```

## Docker Deployment

### Using Docker Compose

```bash
# Start the full stack (edge, control, prometheus, grafana)
docker-compose up -d

# View logs
docker-compose logs -f edge

# Stop
docker-compose down
```

### Building Individual Images

```bash
# Build all images
docker build -t nlag-edge --target edge .
docker build -t nlag-control --target control .
docker build -t nlag-agent --target agent .

# Run edge server
docker run -d -p 4443:4443/udp -p 8080:8080 -p 4040:4040 nlag-edge
```

## Wire Protocol

NLAG uses a binary framed protocol over QUIC streams:

```
+----------------+----------------+------------------+
| Length (4B BE) | Version (1B)   | Payload (N bytes)|
+----------------+----------------+------------------+
```

### Message Types

| Type | Code | Description |
|------|------|-------------|
| AUTH | 0x01 | Agent authentication request |
| AUTH_RESPONSE | 0x02 | Server auth response |
| OPEN_TUNNEL | 0x10 | Request to open tunnel |
| TUNNEL_OPENED | 0x11 | Tunnel opened confirmation |
| CLOSE_TUNNEL | 0x12 | Request to close tunnel |
| DATA | 0x20 | Data frame |
| STREAM_OPEN | 0x22 | New connection stream |
| STREAM_CLOSE | 0x23 | Stream closed |
| PING | 0x30 | Heartbeat ping |
| PONG | 0x31 | Heartbeat pong |
| ERROR | 0x32 | Error message |

## Security

### Transport Security

- TLS 1.3 only (no downgrade attacks)
- QUIC with built-in encryption
- Strong cipher suites

### Authentication

- Token-based authentication
- mTLS support (TODO)
- Short-lived certificates (TODO)

### Defensive Defaults

- Rate limiting per tunnel
- Connection limits
- Strict certificate validation

## TODO: Future Features

- [ ] Let's Encrypt automatic TLS provisioning
- [ ] gRPC tunneling
- [ ] UDP support
- [ ] Multi-region edge deployment
- [ ] Audit logging with log shipping
- [ ] Replay protection
- [ ] API key management UI
- [ ] Billing integration

## Development

### Running Tests

```bash
# Run all tests
cargo test

# Run tests for specific crate
cargo test -p nlag-common

# Run with verbose output
cargo test -- --nocapture
```

### Code Style

```bash
# Format code
cargo fmt

# Lint
cargo clippy
```

## License

Apache 2.0
