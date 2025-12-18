import * as vscode from 'vscode';
import { TunnelManager } from './tunnelManager';
import { TunnelsTreeDataProvider } from './tunnelsView';
import { StatusBarManager } from './statusBar';

let tunnelManager: TunnelManager;
let treeDataProvider: TunnelsTreeDataProvider;
let statusBarManager: StatusBarManager;

export function activate(context: vscode.ExtensionContext) {
    console.log('NLAG Tunnels extension is now active');

    // Initialize managers
    tunnelManager = new TunnelManager(context);
    treeDataProvider = new TunnelsTreeDataProvider(tunnelManager);
    statusBarManager = new StatusBarManager(tunnelManager);

    // Register tree view
    const treeView = vscode.window.createTreeView('nlag.tunnels', {
        treeDataProvider,
        showCollapseAll: false,
    });

    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('nlag.expose', async () => {
            await exposePort();
        }),

        vscode.commands.registerCommand('nlag.exposeQuick', async () => {
            await exposePortQuick();
        }),

        vscode.commands.registerCommand('nlag.listTunnels', async () => {
            treeDataProvider.refresh();
        }),

        vscode.commands.registerCommand('nlag.closeTunnel', async (item) => {
            if (item?.tunnelId) {
                await tunnelManager.closeTunnel(item.tunnelId);
                treeDataProvider.refresh();
                statusBarManager.update();
            }
        }),

        vscode.commands.registerCommand('nlag.closeAllTunnels', async () => {
            await tunnelManager.closeAllTunnels();
            treeDataProvider.refresh();
            statusBarManager.update();
        }),

        vscode.commands.registerCommand('nlag.openInspector', async (item) => {
            if (item?.tunnelId) {
                const tunnel = tunnelManager.getTunnel(item.tunnelId);
                if (tunnel) {
                    const inspectorUrl = `http://localhost:4040/inspect/ui/${item.tunnelId}`;
                    vscode.env.openExternal(vscode.Uri.parse(inspectorUrl));
                }
            }
        }),

        vscode.commands.registerCommand('nlag.copyUrl', async (item) => {
            if (item?.publicUrl) {
                await vscode.env.clipboard.writeText(item.publicUrl);
                vscode.window.showInformationMessage(`Copied: ${item.publicUrl}`);
            }
        }),

        vscode.commands.registerCommand('nlag.login', async () => {
            await login();
        }),

        vscode.commands.registerCommand('nlag.logout', async () => {
            await tunnelManager.logout();
            vscode.window.showInformationMessage('Logged out from NLAG');
        }),

        vscode.commands.registerCommand('nlag.refreshTunnels', async () => {
            treeDataProvider.refresh();
            statusBarManager.update();
        }),

        treeView,
        statusBarManager,
    );

    // Auto-expose on debug if enabled
    context.subscriptions.push(
        vscode.debug.onDidStartDebugSession(async (session) => {
            const config = vscode.workspace.getConfiguration('nlag');
            if (config.get('autoExposeOnDebug')) {
                const port = config.get<number>('debugPort') || 3000;
                try {
                    await tunnelManager.expose({
                        protocol: 'http',
                        localPort: port,
                    });
                    treeDataProvider.refresh();
                    statusBarManager.update();
                } catch (error) {
                    console.error('Failed to auto-expose:', error);
                }
            }
        })
    );
}

async function exposePort(): Promise<void> {
    // Get protocol
    const protocol = await vscode.window.showQuickPick(
        ['http', 'https', 'tcp', 'udp', 'grpc', 'websocket'],
        {
            placeHolder: 'Select protocol',
            title: 'NLAG: Expose Port',
        }
    );

    if (!protocol) {
        return;
    }

    // Get port
    const portStr = await vscode.window.showInputBox({
        prompt: 'Enter local port number',
        placeHolder: '8080',
        validateInput: (value) => {
            const port = parseInt(value, 10);
            if (isNaN(port) || port < 1 || port > 65535) {
                return 'Please enter a valid port number (1-65535)';
            }
            return null;
        },
    });

    if (!portStr) {
        return;
    }

    const port = parseInt(portStr, 10);

    // Get optional subdomain
    const subdomain = await vscode.window.showInputBox({
        prompt: 'Enter subdomain (optional)',
        placeHolder: 'my-app',
    });

    try {
        const tunnel = await tunnelManager.expose({
            protocol: protocol as any,
            localPort: port,
            subdomain: subdomain || undefined,
        });

        vscode.window.showInformationMessage(
            `Tunnel created: ${tunnel.publicUrl}`,
            'Copy URL',
            'Open in Browser'
        ).then((selection) => {
            if (selection === 'Copy URL') {
                vscode.env.clipboard.writeText(tunnel.publicUrl);
            } else if (selection === 'Open in Browser') {
                vscode.env.openExternal(vscode.Uri.parse(tunnel.publicUrl));
            }
        });

        treeDataProvider.refresh();
        statusBarManager.update();
    } catch (error: any) {
        vscode.window.showErrorMessage(`Failed to create tunnel: ${error.message}`);
    }
}

async function exposePortQuick(): Promise<void> {
    const config = vscode.workspace.getConfiguration('nlag');
    const defaultProtocol = config.get<string>('defaultProtocol') || 'http';

    // Quick port input
    const portStr = await vscode.window.showInputBox({
        prompt: 'Enter port to expose',
        placeHolder: '8080',
        validateInput: (value) => {
            const port = parseInt(value, 10);
            if (isNaN(port) || port < 1 || port > 65535) {
                return 'Please enter a valid port number (1-65535)';
            }
            return null;
        },
    });

    if (!portStr) {
        return;
    }

    const port = parseInt(portStr, 10);

    try {
        const tunnel = await tunnelManager.expose({
            protocol: defaultProtocol as any,
            localPort: port,
        });

        vscode.window.showInformationMessage(
            `Tunnel created: ${tunnel.publicUrl}`,
            'Copy URL'
        ).then((selection) => {
            if (selection === 'Copy URL') {
                vscode.env.clipboard.writeText(tunnel.publicUrl);
            }
        });

        treeDataProvider.refresh();
        statusBarManager.update();
    } catch (error: any) {
        vscode.window.showErrorMessage(`Failed to create tunnel: ${error.message}`);
    }
}

async function login(): Promise<void> {
    const authMethod = await vscode.window.showQuickPick(
        ['Email & Password', 'API Token'],
        {
            placeHolder: 'Select authentication method',
            title: 'NLAG: Login',
        }
    );

    if (!authMethod) {
        return;
    }

    if (authMethod === 'API Token') {
        const token = await vscode.window.showInputBox({
            prompt: 'Enter your NLAG API token',
            placeHolder: 'nlag_xxxxxxxxxxxx',
            password: true,
        });

        if (token) {
            try {
                await tunnelManager.loginWithToken(token);
                vscode.window.showInformationMessage('Successfully logged in to NLAG');
            } catch (error: any) {
                vscode.window.showErrorMessage(`Login failed: ${error.message}`);
            }
        }
    } else {
        const email = await vscode.window.showInputBox({
            prompt: 'Enter your email',
            placeHolder: 'user@example.com',
        });

        if (!email) {
            return;
        }

        const password = await vscode.window.showInputBox({
            prompt: 'Enter your password',
            password: true,
        });

        if (password) {
            try {
                await tunnelManager.login(email, password);
                vscode.window.showInformationMessage('Successfully logged in to NLAG');
            } catch (error: any) {
                vscode.window.showErrorMessage(`Login failed: ${error.message}`);
            }
        }
    }
}

export function deactivate() {
    if (tunnelManager) {
        tunnelManager.closeAllTunnels();
    }
}
