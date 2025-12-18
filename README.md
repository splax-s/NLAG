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
- **UDP Tunneling**: Raw UDP port forwarding
- **gRPC Tunneling**: Full gRPC with HTTP/2 support
- **TLS Termination**: Automatic TLS with custom certs (ACME planned)

### ✅ Enterprise Features

- **JWT Authentication**: Secure agent authentication with RS256/HS256
- **Rate Limiting**: Per-tunnel request rate limiting with token bucket
- **Load Balancing**: Multiple strategies (Round Robin, Least Connections, IP Hash, etc.)
- **Connection Pooling**: Efficient connection reuse
- **Custom Domains**: CNAME/TXT verification for custom domain mapping
- **Graceful Shutdown**: Proper connection draining
- **Basic Auth**: Per-tunnel authentication with bcrypt passwords and path exclusions
- **Circuit Breaker**: Automatic failure detection with configurable thresholds
- **IP Restrictions**: Allow/deny lists with CIDR support

### ✅ Request Processing

- **URL Rewriting**: Regex-based path rewriting, redirects, and proxying
- **Header Transformation**: Add, remove, or modify request/response headers
- **Wildcard Domains**: Pattern matching for `*.example.com` routing
- **Custom Error Pages**: Templated HTML/JSON/plain text error responses
- **Event Webhooks**: Tunnel lifecycle events sent to external services
- **Middleware Pipeline**: Unified request/response processing orchestration
- **Webhook Verification**: Validate signatures from Stripe, GitHub, Slack, Discord, etc.

### ✅ Security & Authentication

- **ACME/Let's Encrypt**: Automatic TLS certificate provisioning with HTTP-01 challenges
- **OAuth/OIDC**: Google, GitHub, Microsoft/Azure AD, and generic OIDC providers
- **Traffic Policies**: YAML/JSON configurable rules for routing, auth, transformations
- **JWT Authentication**: Secure agent authentication with RS256/HS256

### ✅ Observability

- **Prometheus Metrics**: Full metrics export for monitoring
- **Request Inspection**: Live HTTP request/response viewer with body capture
- **Request Replay**: Re-send captured requests through tunnel
- **Structured Logging**: JSON logs for aggregation
- **Audit Logging**: Security event tracking with log shipping

### ✅ Developer Experience

- **Terminal UI**: Beautiful TUI with optional widgets (sparkline, latency gauge)
- **Dashboard**: Web-based management interface
- **Docker Support**: Full Docker and docker-compose setup
- **Warning Page**: Security interstitial for first-time browser visits
- **Multi-Region Support**: Deploy edge servers across regions
- **Replay Protection**: Security against request replay attacks

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

# Expose UDP service
cargo run -p nlag-agent -- expose udp 53

# Expose gRPC service
cargo run -p nlag-agent -- expose grpc 50051
```

## CLI Usage

### Agent Commands

```bash
# Expose a local service
nlag expose <protocol> <local_port> [options]

Protocols: http, https, tcp, udp, grpc, websocket, http2

Options:
  -H, --local-host <HOST>   Local host to forward to (default: 127.0.0.1)
  -s, --subdomain <NAME>    Request specific subdomain
  -e, --edge <ADDR>         Edge server address (default: localhost:4443)
  -k, --insecure            Skip TLS verification (dev only)
  -v, --verbose             Enable verbose output
  --no-tui                  Disable TUI, use simple logging
  --sparkline               Show request rate sparkline graph
  --latency-gauge           Show latency gauge visualization
  --request-details         Show detailed request cards
  --health                  Show connection health indicator

# Start tunnels from config file
nlag start --config nlag.yaml

# Start specific group or tunnel
nlag start --config nlag.yaml --group production
nlag start --config nlag.yaml --tunnel web-api

# Config file management
nlag config validate --config nlag.yaml
nlag config example --format yaml
nlag config init --format toml

# Show configuration
nlag config --show

# Show version
nlag version

# Generate shell completions
nlag completions bash > /etc/bash_completion.d/nlag
nlag completions zsh > ~/.zsh/completions/_nlag
nlag completions fish > ~/.config/fish/completions/nlag.fish
```

### Shell Completions

Generate shell completions for your favorite shell:

```bash
# Bash
nlag completions bash > /etc/bash_completion.d/nlag
# Or for user-local installation:
nlag completions bash > ~/.bash_completion.d/nlag

# Zsh
nlag completions zsh > ~/.zsh/completions/_nlag
# Add to your ~/.zshrc: fpath=(~/.zsh/completions $fpath)

# Fish
nlag completions fish > ~/.config/fish/completions/nlag.fish

# PowerShell
nlag completions power-shell > $PROFILE.CurrentUserAllHosts

# Elvish
nlag completions elvish > ~/.elvish/lib/nlag.elv
```

### Agent Config File

Create `nlag.yaml` to manage multiple tunnels:

```yaml
version: "1"
edge_url: "localhost:4443"
insecure: true  # Skip TLS verification (dev only)

tunnels:
  web-api:
    proto: http
    local_addr: "127.0.0.1:3000"
    subdomain: api
    group: backend
    basic_auth:
      - username: admin
        password: secret123
    ip_allow:
      - "10.0.0.0/8"
    ip_deny:
      - "192.168.1.100"

  grpc-service:
    proto: grpc
    local_addr: "127.0.0.1:50051"
    subdomain: grpc
    group: backend

groups:
  backend:
    description: "Backend services"
  frontend:
    description: "Frontend apps"
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

# Expose with TUI widgets
nlag expose http 3000 --sparkline --latency-gauge

# Expose without TUI (for scripts/CI)
nlag expose http 3000 --no-tui

# Expose gRPC service
nlag expose grpc 50051 --subdomain api

# Expose UDP (e.g., DNS or game server)
nlag expose udp 27015 --subdomain gameserver

# Start all tunnels from config
nlag start --config nlag.yaml

# Start only specific group
nlag start --config nlag.yaml --group backend

# Start with file watching (restart on config change)
nlag start --config nlag.yaml --watch

# Generate example config
nlag config example --format yaml > nlag.yaml

# Validate config before starting
nlag config validate --config nlag.yaml
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
- JWT with RS256/HS256
- API key management

### Defensive Defaults

- Rate limiting per tunnel
- Connection limits
- Strict certificate validation
- Replay attack protection
- First-visit warning page for browsers

## Planned Features

### ✅ Recently Implemented

- [x] **ACME/Let's Encrypt** - Automatic TLS certificate provisioning with HTTP-01 challenges
- [x] **Traffic Policy Engine** - YAML/JSON rules for routing, auth, rate limiting, transformations
- [x] **OAuth/OIDC Integration** - Google, GitHub, Azure AD, and generic OIDC authentication
- [x] **Webhook Verification** - Validate webhooks from Stripe, GitHub, Slack, Shopify, Discord, Twilio
- [x] **Request/Response Transformation** - Add/remove/modify headers dynamically
- [x] **URL Rewriting** - Path-based routing, rewrites, and redirects with regex support
- [x] **Basic Auth** - Username/password protection with bcrypt, per-path rules
- [x] **Circuit Breaker** - Automatic failure detection with half-open recovery
- [x] **Wildcard Domains** - Route `*.example.com` to tunnels with pattern matching
- [x] **Custom Error Pages** - Branded HTML/JSON/plain error responses with templates
- [x] **Event Webhooks** - Send tunnel events to external services (start, stop, request, error)
- [x] **Agent Config File** - Start multiple tunnels from YAML/TOML config
- [x] **IP Allowlist/Blocklist** - Restrict access by IP/CIDR ranges
- [x] **Middleware Pipeline** - Unified request/response processing orchestration
- [x] **Endpoint Pooling / Load Balancing** - Multiple agents with round-robin, least-connections, weighted, IP hash strategies
- [x] **File Server Mode** - Serve static files directly with MIME detection, range requests, ETags, directory listing
- [x] **Traffic Policy Actions** - Compress (gzip/brotli) and cache responses via policy rules
- [x] **Reserved Domains** - Persistent subdomains with custom domain verification and wildcard support
- [x] **Request Replay from UI** - One-click replay in inspect interface with full request/response capture
- [x] **SSH Reverse Tunnel** - Create tunnels via SSH with public key auth, session management, subdomain allocation

### ✅ Enterprise Features

- [x] **SSO Integration** - SAML 2.0 support with Okta, Azure AD, OneLogin, Google Workspace
- [x] **Audit Log Export** - Ship to SIEM (Splunk HEC, Datadog, Elasticsearch, CloudWatch, webhooks)
- [x] **Usage Analytics Dashboard** - Traffic insights, bandwidth tracking, latency percentiles, top endpoints
- [x] **Team Management** - Role-based access control with Owner/Admin/Developer/Viewer roles, custom roles, invitations
- [x] **SLA Monitoring** - Uptime tracking, latency percentiles, error rates, tier-based targets, alerting
- [x] **Geo-Restriction** - Block/allow by country/region, ASN blocking, VPN/Tor/proxy detection

### ✅ Developer Experience

- [x] **Agent SDKs** - Python, Node.js/TypeScript, Rust, and Go SDKs with full async support
- [x] **Kubernetes Operator** - Native K8s CRD integration with Tunnel and TunnelConfig resources
- [x] **VS Code Extension** - Start tunnels from IDE with sidebar, status bar, and auto-expose on debug
- [x] **Terraform Provider** - Infrastructure as code support with tunnel, domain, and API key resources
- [x] **CLI Completions** - Shell autocomplete for bash/zsh/fish/PowerShell/elvish

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
