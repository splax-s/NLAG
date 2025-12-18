/**
 * NLAG authentication utilities.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { AuthenticationError } from './errors.js';

/**
 * User credentials for NLAG.
 */
export interface Credentials {
  /** Authentication token */
  token: string;
  /** User ID */
  userId: string;
  /** User email */
  email?: string;
  /** Token expiration timestamp */
  expiresAt?: Date;
  /** Refresh token for token renewal */
  refreshToken?: string;
}

/**
 * Get the path to the credentials file.
 */
export function getCredentialsPath(): string {
  // Check environment variable first
  const envPath = process.env.NLAG_CREDENTIALS_PATH;
  if (envPath) {
    return envPath;
  }

  // Default to ~/.nlag/credentials.json
  return path.join(os.homedir(), '.nlag', 'credentials.json');
}

/**
 * Load credentials from the default location.
 * @returns Credentials if found, null otherwise
 */
export function loadCredentials(): Credentials | null {
  const credPath = getCredentialsPath();

  if (!fs.existsSync(credPath)) {
    return null;
  }

  try {
    const data = JSON.parse(fs.readFileSync(credPath, 'utf-8'));
    return {
      token: data.token,
      userId: data.user_id || data.userId,
      email: data.email,
      expiresAt: data.expires_at ? new Date(data.expires_at) : undefined,
      refreshToken: data.refresh_token || data.refreshToken,
    };
  } catch (error) {
    throw new AuthenticationError(`Invalid credentials file: ${error}`);
  }
}

/**
 * Save credentials to the default location.
 */
export function saveCredentials(credentials: Credentials): void {
  const credPath = getCredentialsPath();
  const dir = path.dirname(credPath);

  // Create directory if needed
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }

  const data = {
    token: credentials.token,
    user_id: credentials.userId,
    email: credentials.email,
    expires_at: credentials.expiresAt?.toISOString(),
    refresh_token: credentials.refreshToken,
  };

  fs.writeFileSync(credPath, JSON.stringify(data, null, 2), { mode: 0o600 });
}

/**
 * Remove stored credentials.
 */
export function clearCredentials(): void {
  const credPath = getCredentialsPath();
  if (fs.existsSync(credPath)) {
    fs.unlinkSync(credPath);
  }
}

/**
 * Check if credentials are expired.
 */
export function isExpired(credentials: Credentials): boolean {
  if (!credentials.expiresAt) {
    return false;
  }
  return new Date() > credentials.expiresAt;
}

/**
 * Authentication options.
 */
export interface AuthenticateOptions {
  /** Control plane server URL */
  server?: string;
}

/** Response from login API */
interface LoginResponse {
  token: string;
  user_id: string;
  expires_at?: string;
  refresh_token?: string;
}

/** Response from refresh API */
interface RefreshResponse {
  token: string;
  expires_at?: string;
  refresh_token?: string;
}

/**
 * Authenticate with the NLAG control plane.
 *
 * @param email - User email address
 * @param password - User password
 * @param options - Additional options
 * @returns Credentials on success
 * @throws AuthenticationError if authentication fails
 *
 * @example
 * ```typescript
 * const credentials = await authenticate('user@example.com', 'password');
 * console.log(`Logged in as ${credentials.email}`);
 * ```
 */
export async function authenticate(
  email: string,
  password: string,
  options: AuthenticateOptions = {}
): Promise<Credentials> {
  const server = options.server || 'https://api.nlag.dev';

  const response = await fetch(`${server}/api/v1/auth/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ email, password }),
  });

  if (response.status === 401) {
    throw new AuthenticationError('Invalid email or password');
  }
  if (response.status === 429) {
    throw new AuthenticationError('Rate limit exceeded, try again later');
  }
  if (!response.ok) {
    throw new AuthenticationError(`Authentication failed: ${response.status}`);
  }

  const data = await response.json() as LoginResponse;

  const credentials: Credentials = {
    token: data.token,
    userId: data.user_id,
    email,
    expiresAt: data.expires_at ? new Date(data.expires_at) : undefined,
    refreshToken: data.refresh_token,
  };

  // Save credentials
  saveCredentials(credentials);

  return credentials;
}

/**
 * Authenticate using an API token.
 *
 * @param token - API token
 * @returns Credentials object
 */
export function authenticateWithToken(token: string): Credentials {
  const credentials: Credentials = {
    token,
    userId: 'api-token',
  };
  saveCredentials(credentials);
  return credentials;
}

/**
 * Refresh an expired token.
 *
 * @param credentials - Current credentials with refresh token
 * @param options - Additional options
 * @returns New credentials
 * @throws AuthenticationError if refresh fails
 */
export async function refreshToken(
  credentials: Credentials,
  options: AuthenticateOptions = {}
): Promise<Credentials> {
  const server = options.server || 'https://api.nlag.dev';

  if (!credentials.refreshToken) {
    throw new AuthenticationError('No refresh token available');
  }

  const response = await fetch(`${server}/api/v1/auth/refresh`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ refresh_token: credentials.refreshToken }),
  });

  if (!response.ok) {
    throw new AuthenticationError('Token refresh failed');
  }

  const data = await response.json() as RefreshResponse;

  const newCredentials: Credentials = {
    token: data.token,
    userId: credentials.userId,
    email: credentials.email,
    expiresAt: data.expires_at ? new Date(data.expires_at) : undefined,
    refreshToken: data.refresh_token || credentials.refreshToken,
  };

  saveCredentials(newCredentials);
  return newCredentials;
}
