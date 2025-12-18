# NLAG Python SDK

Expose local services through secure tunnels with the NLAG Python SDK.

## Installation

```bash
pip install nlag
```

## Quick Start

```python
import asyncio
from nlag import Client

async def main():
    async with Client() as client:
        # Expose local HTTP server on port 8080
        tunnel = await client.expose(local_port=8080, protocol="http")
        print(f"Tunnel URL: {tunnel.public_url}")
        
        # Wait for tunnel to be closed
        await tunnel.wait()

asyncio.run(main())
```

## Authentication

Before using the SDK, authenticate with the NLAG control plane:

```python
from nlag import authenticate

# Login with email/password
credentials = await authenticate("user@example.com", "password")

# Or use an API token
from nlag import Credentials
credentials = Credentials(token="your-api-token", user_id="your-user-id")
```

## Configuration

```python
from nlag import Client, ClientConfig

config = ClientConfig(
    edge_url="edge.nlag.dev:4443",
    control_url="https://api.nlag.dev",
    insecure=False,  # Set True only for development
    connect_timeout=30.0,
    reconnect_enabled=True,
)

async with Client(config) as client:
    tunnel = await client.expose(8080)
```

## Tunnel Configuration

```python
from nlag import TunnelConfig, Protocol

config = TunnelConfig(
    protocol=Protocol.HTTP,
    local_host="127.0.0.1",
    local_port=8080,
    subdomain="myapp",
    basic_auth={"admin": "secret"},
    ip_allow=["10.0.0.0/8"],
    headers={"X-Custom": "value"},
)

tunnel = await client.expose(8080, config=config)
```

## Tunnel Events

```python
tunnel = await client.expose(8080)

@tunnel.on_request
def on_request(request):
    print(f"Request: {request.method} {request.path}")

@tunnel.on_connect
def on_connect():
    print("Connected!")

@tunnel.on_disconnect
def on_disconnect():
    print("Disconnected!")
```

## Metrics

```python
tunnel = await client.expose(8080)

# Get current metrics
metrics = await tunnel.refresh_metrics()
print(f"Total requests: {metrics.requests_total}")
print(f"Bytes in: {metrics.bytes_in}")
print(f"Bytes out: {metrics.bytes_out}")
print(f"Avg latency: {metrics.latency_avg_ms}ms")
```

## Multiple Tunnels

```python
async with Client() as client:
    # Create multiple tunnels
    web = await client.expose(8080, protocol="http", subdomain="web")
    api = await client.expose(3000, protocol="http", subdomain="api")
    db = await client.expose(5432, protocol="tcp")
    
    print(f"Web: {web.public_url}")
    print(f"API: {api.public_url}")
    print(f"DB: {db.public_url}")
    
    # Wait for all tunnels
    await asyncio.gather(web.wait(), api.wait(), db.wait())
```

## Error Handling

```python
from nlag import Client, NlagError, AuthenticationError, TunnelError

try:
    async with Client() as client:
        tunnel = await client.expose(8080)
except AuthenticationError as e:
    print(f"Authentication failed: {e}")
except TunnelError as e:
    print(f"Tunnel error: {e}")
except NlagError as e:
    print(f"NLAG error: {e}")
```

## License

Apache 2.0
