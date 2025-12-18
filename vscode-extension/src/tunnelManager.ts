import * as vscode from 'vscode';
import * as https from 'https';
import * as http from 'http';

export interface TunnelConfig {
    protocol: 'http' | 'https' | 'tcp' | 'udp' | 'grpc' | 'websocket';
    localHost?: string;
    localPort: number;
    subdomain?: string;
    basicAuth?: Record<string, string>;
    ipAllow?: string[];
    ipDeny?: string[];
}

export interface Tunnel {
    id: string;
    publicUrl: string;
    protocol: string;
    localPort: number;
    state: 'connecting' | 'connected' | 'disconnected' | 'closed';
    createdAt: Date;
}

export interface Credentials {
    accessToken: string;
    refreshToken?: string;
    expiresAt?: Date;
}

export class TunnelManager implements vscode.Disposable {
    private tunnels: Map<string, Tunnel> = new Map();
    private credentials: Credentials | null = null;
    private context: vscode.ExtensionContext;

    constructor(context: vscode.ExtensionContext) {
        this.context = context;
        this.loadCredentials();
    }

    dispose(): void {
        this.closeAllTunnels();
    }

    private async loadCredentials(): Promise<void> {
        const stored = await this.context.secrets.get('nlag.credentials');
        if (stored) {
            try {
                this.credentials = JSON.parse(stored);
            } catch {
                this.credentials = null;
            }
        }
    }

    private async saveCredentials(): Promise<void> {
        if (this.credentials) {
            await this.context.secrets.store(
                'nlag.credentials',
                JSON.stringify(this.credentials)
            );
        } else {
            await this.context.secrets.delete('nlag.credentials');
        }
    }

    async login(email: string, password: string): Promise<void> {
        const config = vscode.workspace.getConfiguration('nlag');
        const apiUrl = config.get<string>('apiUrl') || 'https://api.nlag.dev';

        const response = await this.httpPost(`${apiUrl}/auth/login`, {
            email,
            password,
        });

        this.credentials = {
            accessToken: response.access_token,
            refreshToken: response.refresh_token,
            expiresAt: response.expires_at ? new Date(response.expires_at) : undefined,
        };

        await this.saveCredentials();
    }

    async loginWithToken(token: string): Promise<void> {
        const config = vscode.workspace.getConfiguration('nlag');
        const apiUrl = config.get<string>('apiUrl') || 'https://api.nlag.dev';

        // Validate token
        await this.httpGet(`${apiUrl}/auth/me`, token);

        this.credentials = {
            accessToken: token,
        };

        await this.saveCredentials();
    }

    async logout(): Promise<void> {
        this.credentials = null;
        await this.saveCredentials();
    }

    isAuthenticated(): boolean {
        return this.credentials !== null;
    }

    async expose(config: TunnelConfig): Promise<Tunnel> {
        if (!this.credentials) {
            throw new Error('Not authenticated. Please login first.');
        }

        const vscodeConfig = vscode.workspace.getConfiguration('nlag');
        const apiUrl = vscodeConfig.get<string>('apiUrl') || 'https://api.nlag.dev';
        const region = vscodeConfig.get<string>('region');

        const response = await this.httpPost(
            `${apiUrl}/tunnels`,
            {
                protocol: config.protocol,
                local_host: config.localHost || '127.0.0.1',
                local_port: config.localPort,
                subdomain: config.subdomain,
                basic_auth: config.basicAuth,
                ip_allow: config.ipAllow,
                ip_deny: config.ipDeny,
                region,
            },
            this.credentials.accessToken
        );

        const tunnel: Tunnel = {
            id: response.id,
            publicUrl: response.public_url,
            protocol: config.protocol,
            localPort: config.localPort,
            state: 'connected',
            createdAt: new Date(),
        };

        this.tunnels.set(tunnel.id, tunnel);
        return tunnel;
    }

    getTunnel(id: string): Tunnel | undefined {
        return this.tunnels.get(id);
    }

    getTunnels(): Tunnel[] {
        return Array.from(this.tunnels.values());
    }

    async closeTunnel(id: string): Promise<void> {
        if (!this.credentials) {
            throw new Error('Not authenticated');
        }

        const config = vscode.workspace.getConfiguration('nlag');
        const apiUrl = config.get<string>('apiUrl') || 'https://api.nlag.dev';

        try {
            await this.httpDelete(`${apiUrl}/tunnels/${id}`, this.credentials.accessToken);
        } catch {
            // Ignore errors when closing
        }

        this.tunnels.delete(id);
    }

    async closeAllTunnels(): Promise<void> {
        const tunnelIds = Array.from(this.tunnels.keys());
        for (const id of tunnelIds) {
            await this.closeTunnel(id);
        }
    }

    private httpPost(url: string, data: any, token?: string): Promise<any> {
        return new Promise((resolve, reject) => {
            const urlObj = new URL(url);
            const isHttps = urlObj.protocol === 'https:';
            const lib = isHttps ? https : http;

            const postData = JSON.stringify(data);
            const options: https.RequestOptions = {
                hostname: urlObj.hostname,
                port: urlObj.port || (isHttps ? 443 : 80),
                path: urlObj.pathname + urlObj.search,
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(postData),
                    ...(token ? { Authorization: `Bearer ${token}` } : {}),
                },
            };

            const req = lib.request(options, (res) => {
                let body = '';
                res.on('data', (chunk) => (body += chunk));
                res.on('end', () => {
                    if (res.statusCode && res.statusCode >= 400) {
                        reject(new Error(`HTTP ${res.statusCode}: ${body}`));
                    } else {
                        try {
                            resolve(JSON.parse(body));
                        } catch {
                            resolve(body);
                        }
                    }
                });
            });

            req.on('error', reject);
            req.write(postData);
            req.end();
        });
    }

    private httpGet(url: string, token?: string): Promise<any> {
        return new Promise((resolve, reject) => {
            const urlObj = new URL(url);
            const isHttps = urlObj.protocol === 'https:';
            const lib = isHttps ? https : http;

            const options: https.RequestOptions = {
                hostname: urlObj.hostname,
                port: urlObj.port || (isHttps ? 443 : 80),
                path: urlObj.pathname + urlObj.search,
                method: 'GET',
                headers: {
                    ...(token ? { Authorization: `Bearer ${token}` } : {}),
                },
            };

            const req = lib.request(options, (res) => {
                let body = '';
                res.on('data', (chunk) => (body += chunk));
                res.on('end', () => {
                    if (res.statusCode && res.statusCode >= 400) {
                        reject(new Error(`HTTP ${res.statusCode}: ${body}`));
                    } else {
                        try {
                            resolve(JSON.parse(body));
                        } catch {
                            resolve(body);
                        }
                    }
                });
            });

            req.on('error', reject);
            req.end();
        });
    }

    private httpDelete(url: string, token?: string): Promise<void> {
        return new Promise((resolve, reject) => {
            const urlObj = new URL(url);
            const isHttps = urlObj.protocol === 'https:';
            const lib = isHttps ? https : http;

            const options: https.RequestOptions = {
                hostname: urlObj.hostname,
                port: urlObj.port || (isHttps ? 443 : 80),
                path: urlObj.pathname + urlObj.search,
                method: 'DELETE',
                headers: {
                    ...(token ? { Authorization: `Bearer ${token}` } : {}),
                },
            };

            const req = lib.request(options, (res) => {
                let body = '';
                res.on('data', (chunk) => (body += chunk));
                res.on('end', () => {
                    if (res.statusCode && res.statusCode >= 400) {
                        reject(new Error(`HTTP ${res.statusCode}: ${body}`));
                    } else {
                        resolve();
                    }
                });
            });

            req.on('error', reject);
            req.end();
        });
    }
}
