/**
 * NLAG Node.js SDK
 *
 * Expose local services through secure tunnels.
 *
 * @example
 * ```typescript
 * import { Client } from '@nlag/sdk';
 *
 * const client = new Client();
 * await client.connect();
 *
 * const tunnel = await client.expose({
 *   protocol: 'http',
 *   localPort: 8080,
 *   subdomain: 'myapp',
 * });
 *
 * console.log(`Tunnel URL: ${tunnel.publicUrl}`);
 * await tunnel.wait();
 * ```
 *
 * @packageDocumentation
 */

// Client
export { Client, ClientConfig, ClientOptions } from './client.js';

// Tunnel
export {
  Tunnel,
  TunnelConfig,
  TunnelState,
  TunnelMetrics,
  TunnelInfo,
  Protocol,
} from './tunnel.js';

// Auth
export {
  authenticate,
  loadCredentials,
  saveCredentials,
  clearCredentials,
  Credentials,
} from './auth.js';

// Errors
export {
  NlagError,
  AuthenticationError,
  ConnectionError,
  TunnelError,
  ConfigurationError,
  RateLimitError,
  QuotaExceededError,
} from './errors.js';

// Convenience function
export { expose } from './client.js';
