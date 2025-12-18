import * as vscode from 'vscode';
import { TunnelManager, Tunnel } from './tunnelManager.js';

export class TunnelTreeItem extends vscode.TreeItem {
    constructor(
        public readonly tunnel: Tunnel,
        public readonly tunnelId: string,
        public readonly publicUrl: string
    ) {
        super(tunnel.publicUrl, vscode.TreeItemCollapsibleState.None);

        this.contextValue = 'tunnel';
        this.tooltip = new vscode.MarkdownString(
            `**${tunnel.protocol.toUpperCase()}** tunnel\n\n` +
            `- **URL:** ${tunnel.publicUrl}\n` +
            `- **Local:** localhost:${tunnel.localPort}\n` +
            `- **State:** ${tunnel.state}\n` +
            `- **Created:** ${tunnel.createdAt.toLocaleTimeString()}`
        );
        this.description = `→ localhost:${tunnel.localPort}`;

        // Set icon based on protocol
        switch (tunnel.protocol) {
            case 'http':
            case 'https':
                this.iconPath = new vscode.ThemeIcon('globe');
                break;
            case 'tcp':
                this.iconPath = new vscode.ThemeIcon('plug');
                break;
            case 'udp':
                this.iconPath = new vscode.ThemeIcon('radio-tower');
                break;
            case 'grpc':
                this.iconPath = new vscode.ThemeIcon('symbol-method');
                break;
            case 'websocket':
                this.iconPath = new vscode.ThemeIcon('sync');
                break;
            default:
                this.iconPath = new vscode.ThemeIcon('plug');
        }

        // Color based on state
        if (tunnel.state === 'connected') {
            this.iconPath = new vscode.ThemeIcon('pass-filled', new vscode.ThemeColor('testing.iconPassed'));
        } else if (tunnel.state === 'connecting') {
            this.iconPath = new vscode.ThemeIcon('sync~spin');
        } else if (tunnel.state === 'disconnected') {
            this.iconPath = new vscode.ThemeIcon('warning', new vscode.ThemeColor('testing.iconFailed'));
        }
    }
}

export class TunnelsTreeDataProvider implements vscode.TreeDataProvider<TunnelTreeItem> {
    private _onDidChangeTreeData: vscode.EventEmitter<TunnelTreeItem | undefined | void> =
        new vscode.EventEmitter<TunnelTreeItem | undefined | void>();
    readonly onDidChangeTreeData: vscode.Event<TunnelTreeItem | undefined | void> =
        this._onDidChangeTreeData.event;

    constructor(private tunnelManager: TunnelManager) {}

    refresh(): void {
        this._onDidChangeTreeData.fire();
    }

    getTreeItem(element: TunnelTreeItem): vscode.TreeItem {
        return element;
    }

    getChildren(element?: TunnelTreeItem): Thenable<TunnelTreeItem[]> {
        if (element) {
            // No children for tunnel items
            return Promise.resolve([]);
        }

        const tunnels = this.tunnelManager.getTunnels();
        const items = tunnels.map(
            (tunnel) => new TunnelTreeItem(tunnel, tunnel.id, tunnel.publicUrl)
        );

        return Promise.resolve(items);
    }
}
