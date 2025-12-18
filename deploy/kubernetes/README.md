# NLAG Kubernetes Operator

Deploy and manage NLAG tunnels in Kubernetes using Custom Resource Definitions (CRDs).

## Installation

### Install CRDs

```bash
kubectl apply -f https://raw.githubusercontent.com/nlag-dev/nlag/main/deploy/kubernetes/crds/
```

### Install Operator

```bash
kubectl apply -f https://raw.githubusercontent.com/nlag-dev/nlag/main/deploy/kubernetes/operator/
```

Or using Helm:

```bash
helm repo add nlag https://charts.nlag.dev
helm install nlag-operator nlag/nlag-operator
```

## Quick Start

### 1. Create credentials secret

```bash
kubectl create secret generic nlag-credentials \
  --from-literal=token=your-nlag-token
```

### 2. Create a TunnelConfig (optional, for default settings)

```yaml
apiVersion: nlag.dev/v1alpha1
kind: TunnelConfig
metadata:
  name: default
spec:
  edgeServer: edge.nlag.dev:4443
  credentialsSecretRef:
    name: nlag-credentials
    tokenKey: token
  defaultProtocol: http
```

### 3. Create a Tunnel

```yaml
apiVersion: nlag.dev/v1alpha1
kind: Tunnel
metadata:
  name: my-app
spec:
  target:
    service: my-service
    port: 8080
  protocol: http
  subdomain: my-app
```

Apply:

```bash
kubectl apply -f tunnel.yaml
```

Check status:

```bash
kubectl get tunnels
```

Output:

```
NAME     STATE       URL                                  PROTOCOL   TARGET       AGE
my-app   Connected   https://my-app.tunnels.nlag.dev      http       my-service   5m
```

## Examples

### Basic HTTP Tunnel

```yaml
apiVersion: nlag.dev/v1alpha1
kind: Tunnel
metadata:
  name: web
spec:
  target:
    service: web-service
    port: 80
  subdomain: my-web-app
```

### TCP Tunnel (Database)

```yaml
apiVersion: nlag.dev/v1alpha1
kind: Tunnel
metadata:
  name: database
spec:
  target:
    service: postgres
    port: 5432
  protocol: tcp
```

### gRPC Service

```yaml
apiVersion: nlag.dev/v1alpha1
kind: Tunnel
metadata:
  name: grpc-api
spec:
  target:
    service: grpc-service
    port: 50051
  protocol: grpc
  subdomain: api
```

### With Authentication

```yaml
apiVersion: nlag.dev/v1alpha1
kind: Tunnel
metadata:
  name: protected-app
spec:
  target:
    service: app
    port: 8080
  subdomain: protected
  auth:
    basicAuth:
      secretRef:
        name: app-credentials
        key: htpasswd
```

Create the credentials secret:

```bash
# Generate htpasswd-style credentials
kubectl create secret generic app-credentials \
  --from-literal=htpasswd='admin:$2y$10$...'
```

### With IP Restrictions

```yaml
apiVersion: nlag.dev/v1alpha1
kind: Tunnel
metadata:
  name: internal-app
spec:
  target:
    service: internal-service
    port: 8080
  ipPolicy:
    allow:
      - "10.0.0.0/8"
      - "192.168.0.0/16"
    deny:
      - "10.0.1.0/24"  # Except this subnet
```

### With Rate Limiting

```yaml
apiVersion: nlag.dev/v1alpha1
kind: Tunnel
metadata:
  name: rate-limited
spec:
  target:
    service: api
    port: 3000
  subdomain: api
  rateLimit:
    requestsPerSecond: 100
    burstSize: 200
```

### With Custom Headers

```yaml
apiVersion: nlag.dev/v1alpha1
kind: Tunnel
metadata:
  name: with-headers
spec:
  target:
    service: backend
    port: 8080
  headers:
    X-Custom-Header: "custom-value"
    X-Forwarded-Proto: "https"
```

### With Circuit Breaker

```yaml
apiVersion: nlag.dev/v1alpha1
kind: Tunnel
metadata:
  name: resilient-service
spec:
  target:
    service: fragile-service
    port: 8080
  circuitBreaker:
    enabled: true
    failureThreshold: 3
    recoveryTimeout: "60s"
```

### Cross-Namespace Service

```yaml
apiVersion: nlag.dev/v1alpha1
kind: Tunnel
metadata:
  name: cross-ns
spec:
  target:
    service: shared-service
    port: 8080
    namespace: shared-services
  subdomain: shared
```

### Custom Domain

```yaml
apiVersion: nlag.dev/v1alpha1
kind: Tunnel
metadata:
  name: custom-domain
spec:
  target:
    service: web
    port: 80
  customDomain: app.example.com
```

## Tunnel Status

Check tunnel status with:

```bash
kubectl describe tunnel my-app
```

Status fields:

| Field | Description |
|-------|-------------|
| `state` | Current state (Pending, Connecting, Connected, Error) |
| `publicUrl` | Public URL for accessing the tunnel |
| `tunnelId` | Unique tunnel identifier |
| `lastConnected` | Last successful connection time |
| `message` | Human-readable status message |

## TunnelConfig

Set default configuration for all tunnels in a namespace:

```yaml
apiVersion: nlag.dev/v1alpha1
kind: TunnelConfig
metadata:
  name: production
spec:
  edgeServer: edge.nlag.dev:4443
  credentialsSecretRef:
    name: nlag-credentials
  defaultProtocol: http
  defaultHeaders:
    X-Environment: production
  defaultRateLimit:
    requestsPerSecond: 1000
    burstSize: 2000
  defaultCircuitBreaker:
    enabled: true
    failureThreshold: 5
    recoveryTimeout: "30s"
```

## Operator Configuration

Configure the operator using environment variables or command-line flags:

| Variable | Description | Default |
|----------|-------------|---------|
| `NLAG_EDGE_URL` | Default edge server URL | `edge.nlag.dev:4443` |
| `NLAG_RECONCILE_INTERVAL` | Reconciliation interval | `30s` |
| `NLAG_LOG_LEVEL` | Log level (debug, info, warn, error) | `info` |

## Troubleshooting

### Tunnel stuck in Pending state

Check operator logs:

```bash
kubectl logs -n nlag-system deployment/nlag-operator
```

Verify credentials secret exists:

```bash
kubectl get secret nlag-credentials
```

### Tunnel in Error state

Describe the tunnel for error details:

```bash
kubectl describe tunnel my-app
```

Common issues:
- Invalid credentials
- Target service not found
- Rate limit exceeded
- Quota exceeded

### Delete a tunnel

```bash
kubectl delete tunnel my-app
```

## License

Apache 2.0
