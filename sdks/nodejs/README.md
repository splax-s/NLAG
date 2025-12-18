# NLAG Node.js SDK

Expose local services through secure tunnels with the NLAG Node.js SDK.

## Installation

```bash
npm install @nlag/sdk
# or
yarn add @nlag/sdk
# or
pnpm add @nlag/sdk
```

## Quick Start

```typescript
import { Client } from '@nlag/sdk';

const client = new Client();
await client.connect();

const tunnel = await client.expose({
  localPort: 8080,
  protocol: 'http',
  subdomain: 'myapp',
});

console.log(`Tunnel URL: ${tunnel.publicUrl}`);

// Wait for tunnel to be closed
await tunnel.wait();
```

## Authentication

Before using the SDK, authenticate with the NLAG control plane:

```typescript
import { authenticate, authenticateWithToken } from '@nlag/sdk';

// Login with email/password
const credentials = await authenticate('user@example.com', 'password');

// Or use an API token
const credentials = authenticateWithToken('your-api-token');
```

## Configuration

```typescript
import { Client } from '@nlag/sdk';

const client = new Client({
  edgeUrl: 'edge.nlag.dev:4443',
  controlUrl: 'https://api.nlag.dev',
  insecure: false, // Set true only for development
  connectTimeout: 30000,
  reconnectEnabled: true,
});

await client.connect();
const tunnel = await client.expose({ localPort: 8080 });
```

## Tunnel Configuration

```typescript
import { Protocol } from '@nlag/sdk';

const tunnel = await client.expose({
  protocol: Protocol.HTTP,
  localHost: '127.0.0.1',
  localPort: 8080,
  subdomain: 'myapp',
  basicAuth: { admin: 'secret' },
  ipAllow: ['10.0.0.0/8'],
  headers: { 'X-Custom': 'value' },
});
```

## Tunnel Events

```typescript
const tunnel = await client.expose({ localPort: 8080 });

tunnel.on('request', (request) => {
  console.log(`Request: ${request.method} ${request.path}`);
});

tunnel.on('connect', () => {
  console.log('Connected!');
});

tunnel.on('disconnect', () => {
  console.log('Disconnected!');
});

tunnel.on('error', (error) => {
  console.error('Error:', error);
});
```

## Metrics

```typescript
const tunnel = await client.expose({ localPort: 8080 });

// Get current metrics
const metrics = await tunnel.refreshMetrics();
console.log(`Total requests: ${metrics.requestsTotal}`);
console.log(`Bytes in: ${metrics.bytesIn}`);
console.log(`Bytes out: ${metrics.bytesOut}`);
console.log(`Avg latency: ${metrics.latencyAvgMs}ms`);
```

## Multiple Tunnels

```typescript
const client = new Client();
await client.connect();

// Create multiple tunnels
const web = await client.expose({ localPort: 8080, subdomain: 'web' });
const api = await client.expose({ localPort: 3000, subdomain: 'api' });
const db = await client.expose({ localPort: 5432, protocol: 'tcp' });

console.log(`Web: ${web.publicUrl}`);
console.log(`API: ${api.publicUrl}`);
console.log(`DB: ${db.publicUrl}`);

// Wait for all tunnels
await Promise.all([web.wait(), api.wait(), db.wait()]);
```

## Convenience Methods

```typescript
// HTTP
const httpTunnel = await client.exposeHttp(8080, { subdomain: 'web' });

// TCP
const tcpTunnel = await client.exposeTcp(5432);

// UDP
const udpTunnel = await client.exposeUdp(27015);

// gRPC
const grpcTunnel = await client.exposeGrpc(50051);
```

## Error Handling

```typescript
import {
  Client,
  NlagError,
  AuthenticationError,
  TunnelError,
} from '@nlag/sdk';

try {
  const client = new Client();
  await client.connect();
  const tunnel = await client.expose({ localPort: 8080 });
} catch (error) {
  if (error instanceof AuthenticationError) {
    console.error(`Authentication failed: ${error.message}`);
  } else if (error instanceof TunnelError) {
    console.error(`Tunnel error: ${error.message}`);
  } else if (error instanceof NlagError) {
    console.error(`NLAG error: ${error.message}`);
  }
}
```

## TypeScript Support

This SDK is written in TypeScript and includes full type definitions.

```typescript
import type { TunnelConfig, TunnelMetrics, ClientConfig } from '@nlag/sdk';

const config: TunnelConfig = {
  localPort: 8080,
  protocol: 'http',
  subdomain: 'myapp',
};

const tunnel = await client.expose(config);
const metrics: TunnelMetrics = await tunnel.refreshMetrics();
```

## License

Apache 2.0
