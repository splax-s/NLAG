# NLAG Terraform Provider

The NLAG Terraform provider allows you to manage NLAG tunnels, domains, and other resources as infrastructure as code.

## Requirements

- Terraform 1.0+
- NLAG account with API access

## Installation

### From Terraform Registry

```hcl
terraform {
  required_providers {
    nlag = {
      source  = "nlag/nlag"
      version = "~> 0.1"
    }
  }
}
```

### From Source

```bash
go build -o terraform-provider-nlag
mkdir -p ~/.terraform.d/plugins/registry.terraform.io/nlag/nlag/0.1.0/darwin_arm64
mv terraform-provider-nlag ~/.terraform.d/plugins/registry.terraform.io/nlag/nlag/0.1.0/darwin_arm64/
```

## Provider Configuration

```hcl
provider "nlag" {
  # API URL (optional, defaults to https://api.nlag.dev)
  api_url = "https://api.nlag.dev"
  
  # API token (required, can also use NLAG_API_TOKEN env var)
  api_token = var.nlag_api_token
  
  # Preferred region (optional)
  region = "us-west"
}
```

### Environment Variables

- `NLAG_API_URL` - API endpoint
- `NLAG_API_TOKEN` - API authentication token
- `NLAG_REGION` - Default region for resources

## Resources

### nlag_tunnel

Manages an NLAG tunnel.

```hcl
resource "nlag_tunnel" "web" {
  protocol   = "http"
  local_port = 3000
  subdomain  = "my-app"
  
  # Optional: Basic authentication
  basic_auth = {
    admin = "secret-password"
  }
  
  # Optional: IP restrictions
  ip_allow = ["10.0.0.0/8", "192.168.1.0/24"]
  ip_deny  = ["192.168.1.100"]
  
  # Optional: Custom headers
  headers = {
    "X-Forwarded-Host" = "my-app.example.com"
  }
  
  # Optional: Region
  region = "us-west"
}

output "tunnel_url" {
  value = nlag_tunnel.web.public_url
}
```

#### Arguments

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| `protocol` | string | Yes | Protocol: http, https, tcp, udp, grpc, websocket |
| `local_port` | number | Yes | Local port to forward traffic to |
| `subdomain` | string | No | Requested subdomain |
| `basic_auth` | map(string) | No | Username to password mapping |
| `ip_allow` | list(string) | No | Allowed CIDR ranges |
| `ip_deny` | list(string) | No | Denied CIDR ranges |
| `headers` | map(string) | No | Custom headers |
| `region` | string | No | Preferred region |

#### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `id` | string | Tunnel ID |
| `public_url` | string | Public URL |
| `state` | string | Tunnel state |

### nlag_domain

Manages a custom domain.

```hcl
resource "nlag_domain" "custom" {
  domain    = "api.example.com"
  tunnel_id = nlag_tunnel.web.id
}

output "verification_txt" {
  value = nlag_domain.custom.verification_txt
}
```

#### Arguments

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| `domain` | string | Yes | Domain name |
| `tunnel_id` | string | No | Tunnel to route traffic to |
| `certificate` | string | No | Custom TLS certificate (PEM) |
| `private_key` | string | No | Custom TLS private key (PEM) |

### nlag_api_key

Manages an API key.

```hcl
resource "nlag_api_key" "ci" {
  name        = "CI/CD Pipeline"
  permissions = ["tunnels:read", "tunnels:write"]
  expires_at  = "2025-12-31T23:59:59Z"
}

output "api_key" {
  value     = nlag_api_key.ci.key
  sensitive = true
}
```

### nlag_ip_restriction

Manages IP restrictions for a tunnel.

```hcl
resource "nlag_ip_restriction" "office" {
  tunnel_id   = nlag_tunnel.web.id
  type        = "allow"
  cidr        = "203.0.113.0/24"
  description = "Office network"
}
```

## Data Sources

### nlag_tunnel

Fetch an existing tunnel.

```hcl
data "nlag_tunnel" "existing" {
  id = "tun_xxxxx"
}
```

### nlag_domains

List all domains.

```hcl
data "nlag_domains" "all" {}

output "domain_count" {
  value = length(data.nlag_domains.all.domains)
}
```

### nlag_regions

List available regions.

```hcl
data "nlag_regions" "available" {}

output "regions" {
  value = [for r in data.nlag_regions.available.regions : r.id if r.available]
}
```

## Examples

### Development Environment

```hcl
# Expose local development server
resource "nlag_tunnel" "dev" {
  protocol   = "http"
  local_port = 3000
  subdomain  = "dev-${var.developer_name}"
}

# Expose database for remote access
resource "nlag_tunnel" "db" {
  protocol   = "tcp"
  local_port = 5432
  
  ip_allow = [var.office_cidr]
}
```

### Production Webhook Receiver

```hcl
resource "nlag_tunnel" "webhooks" {
  protocol   = "https"
  local_port = 8080
  subdomain  = "webhooks"
  
  headers = {
    "X-Webhook-Secret" = var.webhook_secret
  }
}

resource "nlag_domain" "webhooks" {
  domain    = "webhooks.${var.domain}"
  tunnel_id = nlag_tunnel.webhooks.id
}
```

### Multi-Region Deployment

```hcl
locals {
  regions = ["us-west", "us-east", "eu-west"]
}

resource "nlag_tunnel" "api" {
  for_each = toset(local.regions)
  
  protocol   = "grpc"
  local_port = 50051
  subdomain  = "api-${each.key}"
  region     = each.key
}
```

## Import

Resources can be imported using their ID:

```bash
terraform import nlag_tunnel.web tun_xxxxx
terraform import nlag_domain.custom dom_xxxxx
```

## Development

### Building

```bash
go build -o terraform-provider-nlag
```

### Testing

```bash
go test ./...
```

### Generating Documentation

```bash
go generate ./...
```

## License

MIT
