/**
 * Custom error classes for NLAG SDK.
 */

/**
 * Base error class for all NLAG errors.
 */
export class NlagError extends Error {
  /** Error code for programmatic handling */
  readonly code: string;

  constructor(message: string, code: string = 'NLAG_ERROR') {
    super(message);
    this.name = 'NlagError';
    this.code = code;
    Object.setPrototypeOf(this, NlagError.prototype);
  }
}

/**
 * Thrown when authentication fails.
 */
export class AuthenticationError extends NlagError {
  constructor(message: string = 'Authentication failed') {
    super(message, 'AUTH_ERROR');
    this.name = 'AuthenticationError';
    Object.setPrototypeOf(this, AuthenticationError.prototype);
  }
}

/**
 * Thrown when connection to the edge server fails.
 */
export class ConnectionError extends NlagError {
  constructor(message: string = 'Connection failed') {
    super(message, 'CONNECTION_ERROR');
    this.name = 'ConnectionError';
    Object.setPrototypeOf(this, ConnectionError.prototype);
  }
}

/**
 * Thrown when tunnel operations fail.
 */
export class TunnelError extends NlagError {
  /** Tunnel ID if available */
  readonly tunnelId?: string;

  constructor(message: string, tunnelId?: string) {
    super(message, 'TUNNEL_ERROR');
    this.name = 'TunnelError';
    this.tunnelId = tunnelId;
    Object.setPrototypeOf(this, TunnelError.prototype);
  }
}

/**
 * Thrown when configuration is invalid.
 */
export class ConfigurationError extends NlagError {
  /** Field that has the invalid value */
  readonly field?: string;

  constructor(message: string, field?: string) {
    super(message, 'CONFIG_ERROR');
    this.name = 'ConfigurationError';
    this.field = field;
    Object.setPrototypeOf(this, ConfigurationError.prototype);
  }
}

/**
 * Thrown when rate limit is exceeded.
 */
export class RateLimitError extends NlagError {
  /** Seconds until rate limit resets */
  readonly retryAfter?: number;

  constructor(retryAfter?: number) {
    super('Rate limit exceeded', 'RATE_LIMIT');
    this.name = 'RateLimitError';
    this.retryAfter = retryAfter;
    Object.setPrototypeOf(this, RateLimitError.prototype);
  }
}

/**
 * Thrown when quota is exceeded.
 */
export class QuotaExceededError extends NlagError {
  /** Type of quota exceeded */
  readonly quotaType: string;
  /** Maximum allowed */
  readonly limit: number;
  /** Current usage */
  readonly current: number;

  constructor(quotaType: string, limit: number, current: number) {
    super(`Quota exceeded for ${quotaType}: ${current}/${limit}`, 'QUOTA_EXCEEDED');
    this.name = 'QuotaExceededError';
    this.quotaType = quotaType;
    this.limit = limit;
    this.current = current;
    Object.setPrototypeOf(this, QuotaExceededError.prototype);
  }
}
