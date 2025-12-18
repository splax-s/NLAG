/**
 * NLAG client for managing tunnels.
 */

import { loadCredentials, Credentials, isExpired } from './auth.js';
import {
  AuthenticationError,
  ConfigurationError,
  ConnectionError,
  TunnelError,
} from './errors.js';
import { Protocol, Tunnel, TunnelConfig, TunnelInfo, TunnelState } from './tunnel.js';

/**
 * Client configuration options.
 */
export interface ClientConfig {
  /** Edge server address */
  edgeUrl?: string;
  /** Control plane server URL */
  controlUrl?: string;
  /** Skip TLS verification (DANGEROUS - development only) */
  insecure?: boolean;
  /** Connection timeout in milliseconds */
  connectTimeout?: number;
  /** Enable automatic reconnection */
  reconnectEnabled?: boolean;
  /** Initial reconnect delay in milliseconds */
  reconnectDelay?: number;
  /** Maximum reconnect delay in milliseconds */
  maxReconnectDelay?: number;
  /** Maximum reconnect attempts (0 = infinite) */
  maxReconnectAttempts?: number;
  /** Pre-loaded credentials */
  credentials?: Credentials;
  /** Custom CA certificate path */
  caCert?: string;
  /** Additional metadata for tunnels */
  metadata?: Record<string, unknown>;
}

/**
 * Options for creating a client.
 */
export type ClientOptions = ClientConfig;

/**
 * NLAG client for creating and managing tunnels.
 *
 * @example
 * ```typescript
 * const client = new Client({ edgeUrl: 'edge.nlag.dev:4443' });
 * await client.connect();
 *
 * const tunnel = await client.expose({ localPort: 8080, subdomain: 'myapp' });
 * console.log(`URL: ${tunnel.publicUrl}`);
 *
 * await tunnel.wait();
 * await client.close();
 * ```
 */
export class Client {
  private readonly config: Required<ClientConfig>;
  private connected = false;
  private readonly tunnels = new Map<string, Tunnel>();
  private connection: unknown = null;
  private credentials: Credentials | null = null;

  constructor(options: ClientOptions = {}) {
    this.config = {
      edgeUrl: options.edgeUrl || 'localhost:4443',
      controlUrl: options.controlUrl || 'https://api.nlag.dev',
      insecure: options.insecure || false,
      connectTimeout: options.connectTimeout || 30000,
      reconnectEnabled: options.reconnectEnabled ?? true,
      reconnectDelay: options.reconnectDelay || 1000,
      maxReconnectDelay: options.maxReconnectDelay || 30000,
      maxReconnectAttempts: options.maxReconnectAttempts || 0,
      credentials: options.credentials || null!,
      caCert: options.caCert || null!,
      metadata: options.metadata || {},
    };

    this.credentials = options.credentials || null;
    this.validate();
  }

  private validate(): void {
    if (!this.config.edgeUrl) {
      throw new ConfigurationError('edgeUrl is required', 'edgeUrl');
    }
    if (this.config.connectTimeout <= 0) {
      throw new ConfigurationError('connectTimeout must be positive', 'connectTimeout');
    }
  }

  /** Whether the client is connected to the edge server */
  get isConnected(): boolean {
    return this.connected;
  }

  /** List of active tunnels */
  get activeTunnels(): Tunnel[] {
    return Array.from(this.tunnels.values());
  }

  /**
   * Connect to the edge server.
   */
  async connect(): Promise<void> {
    if (this.connected) {
      return;
    }

    // Load credentials if not provided
    if (!this.credentials) {
      this.credentials = loadCredentials();
      if (!this.credentials) {
        throw new AuthenticationError(
          'No credentials found. Run `nlag login` or provide credentials.'
        );
      }
    }

    // Check if credentials are expired
    if (isExpired(this.credentials)) {
      throw new AuthenticationError('Credentials have expired. Please log in again.');
    }

    try {
      // TODO: Create QUIC connection to edge server
      // For now, just mark as connected
      this.connected = true;
    } catch (error) {
      throw new ConnectionError(`Failed to connect to edge server: ${error}`);
    }
  }

  /**
   * Close the client and all tunnels.
   */
  async close(): Promise<void> {
    // Close all tunnels
    const closePromises = Array.from(this.tunnels.values()).map((t) =>
      t.close().catch(() => {})
    );
    await Promise.all(closePromises);

    this.tunnels.clear();
    this.connection = null;
    this.connected = false;
  }

  /**
   * Expose a local service through a tunnel.
   *
   * @param config - Tunnel configuration
   * @returns Active tunnel
   * @throws TunnelError if tunnel creation fails
   */
  async expose(config: TunnelConfig): Promise<Tunnel> {
    if (!this.connected) {
      await this.connect();
    }

    // Normalize protocol
    let protocol: Protocol;
    if (typeof config.protocol === 'string') {
      protocol = config.protocol.toLowerCase() as Protocol;
    } else {
      protocol = config.protocol || Protocol.HTTP;
    }

    const fullConfig: TunnelConfig = {
      protocol,
      localHost: config.localHost || '127.0.0.1',
      localPort: config.localPort,
      subdomain: config.subdomain,
      basicAuth: config.basicAuth,
      ipAllow: config.ipAllow,
      ipDeny: config.ipDeny,
      headers: config.headers,
      inspect: config.inspect ?? true,
      metadata: { ...this.config.metadata, ...config.metadata },
    };

    try {
      // TODO: Create tunnel through QUIC connection
      // For now, create mock tunnel
      const tunnelId = crypto.randomUUID();
      const subdomain = config.subdomain || tunnelId.substring(0, 8);

      const tunnel = new Tunnel(
        tunnelId,
        `https://${subdomain}.tunnels.nlag.dev`,
        fullConfig,
        this.connection
      );

      this.tunnels.set(tunnelId, tunnel);
      tunnel._setState(TunnelState.Connected);

      return tunnel;
    } catch (error) {
      throw new TunnelError(`Failed to create tunnel: ${error}`);
    }
  }

  /**
   * Convenience method to expose an HTTP service.
   */
  async exposeHttp(localPort: number, options: Omit<TunnelConfig, 'localPort' | 'protocol'> = {}): Promise<Tunnel> {
    return this.expose({ ...options, localPort, protocol: Protocol.HTTP });
  }

  /**
   * Convenience method to expose a TCP service.
   */
  async exposeTcp(localPort: number, options: Omit<TunnelConfig, 'localPort' | 'protocol'> = {}): Promise<Tunnel> {
    return this.expose({ ...options, localPort, protocol: Protocol.TCP });
  }

  /**
   * Convenience method to expose a UDP service.
   */
  async exposeUdp(localPort: number, options: Omit<TunnelConfig, 'localPort' | 'protocol'> = {}): Promise<Tunnel> {
    return this.expose({ ...options, localPort, protocol: Protocol.UDP });
  }

  /**
   * Convenience method to expose a gRPC service.
   */
  async exposeGrpc(localPort: number, options: Omit<TunnelConfig, 'localPort' | 'protocol'> = {}): Promise<Tunnel> {
    return this.expose({ ...options, localPort, protocol: Protocol.GRPC });
  }

  /**
   * List all tunnels for the authenticated user.
   */
  async listTunnels(): Promise<TunnelInfo[]> {
    if (!this.connected) {
      await this.connect();
    }

    // TODO: Query tunnels from edge server
    return [];
  }

  /**
   * Get a tunnel by ID.
   */
  getTunnel(tunnelId: string): Tunnel | undefined {
    return this.tunnels.get(tunnelId);
  }

  /**
   * Close a specific tunnel.
   */
  async closeTunnel(tunnelId: string): Promise<void> {
    const tunnel = this.tunnels.get(tunnelId);
    if (tunnel) {
      await tunnel.close();
      this.tunnels.delete(tunnelId);
    }
  }

  toString(): string {
    const status = this.connected ? 'connected' : 'disconnected';
    return `Client(edge=${this.config.edgeUrl}, status=${status}, tunnels=${this.tunnels.size})`;
  }
}

/**
 * Quick function to expose a local service.
 *
 * @param config - Tunnel configuration
 * @param clientOptions - Client options
 * @returns Active tunnel
 *
 * @example
 * ```typescript
 * const tunnel = await expose({ localPort: 8080, subdomain: 'myapp' });
 * console.log(`URL: ${tunnel.publicUrl}`);
 * await tunnel.wait();
 * ```
 */
export async function expose(
  config: TunnelConfig,
  clientOptions: ClientOptions = {}
): Promise<Tunnel> {
  const client = new Client(clientOptions);
  await client.connect();
  return client.expose(config);
}
