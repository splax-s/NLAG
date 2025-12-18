# NLAG Go SDK

Official Go SDK for NLAG - expose local services through secure tunnels.

## Installation

```bash
go get github.com/splax-s/nlag-go
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"
    "os/signal"
    "syscall"

    "github.com/splax-s/nlag-go"
)

func main() {
    ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
    defer cancel()

    // Create client (uses stored credentials)
    client, err := nlag.NewClient()
    if err != nil {
        log.Fatal(err)
    }

    // Expose port 8080 with HTTP
    tunnel, err := client.Expose(ctx, &nlag.TunnelConfig{
        Protocol:  nlag.ProtocolHTTP,
        LocalPort: 8080,
        Subdomain: "my-app",
    })
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("Tunnel URL:", tunnel.PublicURL())

    // Wait for shutdown signal
    <-ctx.Done()
    tunnel.Close()
}
```

## Authentication

### Login with Email/Password

```go
creds, err := nlag.Authenticate("user@example.com", "password", nil)
if err != nil {
    log.Fatal(err)
}
```

### Login with API Token

```go
creds, err := nlag.AuthenticateWithToken("nlag_xxxxxxxxxxxx", nil)
if err != nil {
    log.Fatal(err)
}
```

### Load Stored Credentials

```go
creds, err := nlag.LoadCredentials()
if err != nil {
    log.Fatal(err)
}
```

## Client Configuration

```go
client, err := nlag.NewClientWithConfig(&nlag.ClientConfig{
    APIURL:        "https://api.nlag.dev",
    EdgeURL:       "wss://connect.nlag.dev",
    Region:        "us-west",
    Timeout:       30 * time.Second,
    AutoReconnect: true,
    MaxRetries:    5,
    VerifyTLS:     true,
})
```

## Tunnel Configuration

```go
config := &nlag.TunnelConfig{
    Protocol:  nlag.ProtocolHTTP,
    LocalHost: "127.0.0.1",
    LocalPort: 3000,
    Subdomain: "api",
    
    // Basic auth
    BasicAuth: map[string]string{
        "admin": "secret",
    },
    
    // IP restrictions
    IPAllow: []string{"10.0.0.0/8"},
    IPDeny:  []string{"192.168.1.100"},
    
    // Custom headers
    Headers: map[string]string{
        "X-Custom": "value",
    },
    
    // Enable request inspection
    Inspect: true,
    
    // Custom metadata
    Metadata: map[string]interface{}{
        "env": "development",
    },
}
```

## Working with Tunnels

### Create a Tunnel

```go
tunnel, err := client.Expose(ctx, &nlag.TunnelConfig{
    LocalPort: 8080,
})
if err != nil {
    log.Fatal(err)
}

fmt.Println("ID:", tunnel.ID())
fmt.Println("URL:", tunnel.PublicURL())
fmt.Println("State:", tunnel.State())
```

### List Tunnels

```go
tunnels, err := client.ListTunnels(ctx)
if err != nil {
    log.Fatal(err)
}

for _, t := range tunnels {
    fmt.Printf("%s: %s -> %s\n", t.ID, t.PublicURL, t.LocalAddress)
}
```

### Get Tunnel Info

```go
info, err := client.GetTunnel(ctx, "tunnel-id")
if err != nil {
    log.Fatal(err)
}
fmt.Println("Requests:", info.Metrics.RequestsTotal)
```

### Close Tunnel

```go
// Close specific tunnel
tunnel.Close()

// Or by ID
client.CloseTunnel(ctx, "tunnel-id")

// Close all tunnels
client.CloseAll(ctx)
```

### State Changes

```go
tunnel.OnStateChange(func(state nlag.TunnelState) {
    fmt.Println("State changed to:", state)
})
```

## Protocols

| Protocol | Description |
|----------|-------------|
| `ProtocolHTTP` | HTTP traffic |
| `ProtocolHTTPS` | HTTPS with TLS termination |
| `ProtocolTCP` | Raw TCP connections |
| `ProtocolUDP` | UDP datagrams |
| `ProtocolGRPC` | gRPC traffic |
| `ProtocolWebSocket` | WebSocket connections |

## Error Handling

```go
import "errors"

tunnel, err := client.Expose(ctx, config)
if err != nil {
    var apiErr *nlag.APIError
    if errors.As(err, &apiErr) {
        if apiErr.IsRateLimited() {
            fmt.Println("Rate limited, try again later")
        } else if apiErr.IsUnauthorized() {
            fmt.Println("Invalid credentials")
        } else {
            fmt.Printf("API error: %s\n", apiErr.Message)
        }
    } else if errors.Is(err, nlag.ErrNotAuthenticated) {
        fmt.Println("Please login first")
    } else {
        fmt.Printf("Error: %v\n", err)
    }
    return
}
```

## Examples

### HTTP Server with Tunnel

```go
package main

import (
    "context"
    "fmt"
    "log"
    "net/http"
    "os/signal"
    "syscall"

    "github.com/splax-s/nlag-go"
)

func main() {
    ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
    defer cancel()

    // Start local server
    go func() {
        http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
            fmt.Fprintln(w, "Hello from NLAG!")
        })
        http.ListenAndServe(":3000", nil)
    }()

    // Create tunnel
    client, err := nlag.NewClient()
    if err != nil {
        log.Fatal(err)
    }

    tunnel, err := client.Expose(ctx, &nlag.TunnelConfig{
        Protocol:  nlag.ProtocolHTTP,
        LocalPort: 3000,
    })
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("Server available at:", tunnel.PublicURL())
    
    <-ctx.Done()
}
```

### Multiple Tunnels

```go
client, err := nlag.NewClient()
if err != nil {
    log.Fatal(err)
}

httpTunnel, err := client.Expose(ctx, &nlag.TunnelConfig{
    Protocol:  nlag.ProtocolHTTP,
    LocalPort: 8080,
    Subdomain: "web",
})
if err != nil {
    log.Fatal(err)
}

grpcTunnel, err := client.Expose(ctx, &nlag.TunnelConfig{
    Protocol:  nlag.ProtocolGRPC,
    LocalPort: 50051,
    Subdomain: "api",
})
if err != nil {
    log.Fatal(err)
}

fmt.Println("Web:", httpTunnel.PublicURL())
fmt.Println("API:", grpcTunnel.PublicURL())
```

## License

MIT
