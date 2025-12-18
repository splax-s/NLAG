/**
 * NLAG tunnel management.
 */

import { EventEmitter } from 'events';

/**
 * Tunnel connection states.
 */
export enum TunnelState {
  /** Connecting to edge server */
  Connecting = 'connecting',
  /** Connected and forwarding traffic */
  Connected = 'connected',
  /** Reconnecting after disconnect */
  Reconnecting = 'reconnecting',
  /** Disconnected from edge server */
  Disconnected = 'disconnected',
  /** Tunnel has been closed */
  Closed = 'closed',
  /** Tunnel is in error state */
  Error = 'error',
}

/**
 * Supported tunnel protocols.
 */
export enum Protocol {
  HTTP = 'http',
  HTTPS = 'https',
  TCP = 'tcp',
  UDP = 'udp',
  GRPC = 'grpc',
  WebSocket = 'websocket',
}

/**
 * Configuration for creating a tunnel.
 */
export interface TunnelConfig {
  /** Protocol to use */
  protocol?: Protocol | string;
  /** Local host to forward to */
  localHost?: string;
  /** Local port to forward to */
  localPort: number;
  /** Requested subdomain */
  subdomain?: string;
  /** Basic auth credentials */
  basicAuth?: Record<string, string>;
  /** IP allowlist (CIDR notation) */
  ipAllow?: string[];
  /** IP denylist (CIDR notation) */
  ipDeny?: string[];
  /** Custom headers to add */
  headers?: Record<string, string>;
  /** Enable request inspection */
  inspect?: boolean;
  /** Custom metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Tunnel usage metrics.
 */
export interface TunnelMetrics {
  /** Total number of requests */
  requestsTotal: number;
  /** Bytes received */
  bytesIn: number;
  /** Bytes sent */
  bytesOut: number;
  /** Currently active connections */
  connectionsActive: number;
  /** Average latency in milliseconds */
  latencyAvgMs: number;
  /** 99th percentile latency in milliseconds */
  latencyP99Ms: number;
  /** Total number of errors */
  errorsTotal: number;
  /** Last request timestamp */
  lastRequestAt?: Date;
}

/**
 * Information about an existing tunnel.
 */
export interface TunnelInfo {
  /** Unique tunnel ID */
  id: string;
  /** Public URL */
  publicUrl: string;
  /** Protocol */
  protocol: Protocol;
  /** Local address being forwarded */
  localAddress: string;
  /** Current state */
  state: TunnelState;
  /** Creation timestamp */
  createdAt: Date;
  /** Tunnel metrics */
  metrics: TunnelMetrics;
  /** Custom metadata */
  metadata: Record<string, unknown>;
}

/**
 * Represents an active tunnel connection.
 *
 * @example
 * ```typescript
 * const tunnel = await client.expose({ localPort: 8080 });
 *
 * tunnel.on('request', (req) => {
 *   console.log(`Request: ${req.method} ${req.path}`);
 * });
 *
 * tunnel.on('connect', () => console.log('Connected!'));
 * tunnel.on('disconnect', () => console.log('Disconnected!'));
 *
 * console.log(`URL: ${tunnel.publicUrl}`);
 * await tunnel.wait();
 * ```
 */
export class Tunnel extends EventEmitter {
  private readonly _id: string;
  private readonly _publicUrl: string;
  private readonly _config: TunnelConfig;
  private _state: TunnelState;
  private _metrics: TunnelMetrics;
  private readonly _createdAt: Date;
  private _closePromise: Promise<void> | null = null;
  private _closeResolve: (() => void) | null = null;

  constructor(
    tunnelId: string,
    publicUrl: string,
    config: TunnelConfig,
    private readonly connection: unknown // Internal connection object
  ) {
    super();
    this._id = tunnelId;
    this._publicUrl = publicUrl;
    this._config = config;
    this._state = TunnelState.Connecting;
    this._createdAt = new Date();
    this._metrics = {
      requestsTotal: 0,
      bytesIn: 0,
      bytesOut: 0,
      connectionsActive: 0,
      latencyAvgMs: 0,
      latencyP99Ms: 0,
      errorsTotal: 0,
    };
  }

  /** Unique tunnel identifier */
  get id(): string {
    return this._id;
  }

  /** Public URL for accessing the tunnel */
  get publicUrl(): string {
    return this._publicUrl;
  }

  /** Current tunnel state */
  get state(): TunnelState {
    return this._state;
  }

  /** Current tunnel metrics */
  get metrics(): TunnelMetrics {
    return { ...this._metrics };
  }

  /** Tunnel configuration */
  get config(): TunnelConfig {
    return { ...this._config };
  }

  /** When the tunnel was created */
  get createdAt(): Date {
    return this._createdAt;
  }

  /**
   * Wait for the tunnel to be closed.
   */
  async wait(): Promise<void> {
    if (this._state === TunnelState.Closed) {
      return;
    }

    if (!this._closePromise) {
      this._closePromise = new Promise((resolve) => {
        this._closeResolve = resolve;
      });
    }

    return this._closePromise;
  }

  /**
   * Close the tunnel.
   */
  async close(): Promise<void> {
    if (this._state === TunnelState.Closed) {
      return;
    }

    this._state = TunnelState.Closed;
    this.emit('close');

    if (this._closeResolve) {
      this._closeResolve();
    }
  }

  /**
   * Refresh and return current metrics.
   */
  async refreshMetrics(): Promise<TunnelMetrics> {
    // TODO: Fetch metrics from connection
    return this._metrics;
  }

  /**
   * Update internal state.
   * @internal
   */
  _setState(state: TunnelState): void {
    const oldState = this._state;
    this._state = state;
    this.emit('stateChange', { oldState, newState: state });

    if (state === TunnelState.Connected) {
      this.emit('connect');
    } else if (state === TunnelState.Disconnected) {
      this.emit('disconnect');
    } else if (state === TunnelState.Error) {
      this.emit('error', new Error('Tunnel error'));
    }
  }

  /**
   * Update metrics.
   * @internal
   */
  _updateMetrics(metrics: Partial<TunnelMetrics>): void {
    this._metrics = { ...this._metrics, ...metrics };
  }

  toString(): string {
    return `Tunnel(id=${this._id}, url=${this._publicUrl}, state=${this._state})`;
  }
}
