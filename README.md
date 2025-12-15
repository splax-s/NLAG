# NLAG - Next-Generation Low-Latency Access Gateway

A production-grade secure tunneling platform built in Rust, providing:
- Zero-trust security with mTLS
- Low-latency QUIC transport
- High concurrency through stream multiplexing
- Enterprise-ready architecture

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
```

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

## TODO: Enterprise Features

- [ ] mTLS client authentication
- [ ] JWT/OAuth2 integration
- [ ] IP allowlisting
- [ ] Custom domains with automatic TLS
- [ ] WebSocket protocol support
- [ ] gRPC tunneling
- [ ] UDP support
- [ ] Multi-region edge deployment
- [ ] Metrics and observability
- [ ] Admin dashboard
- [ ] Audit logging
- [ ] Replay protection

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
