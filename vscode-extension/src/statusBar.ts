import * as vscode from 'vscode';
import { TunnelManager } from './tunnelManager.js';

export class StatusBarManager implements vscode.Disposable {
    private statusBarItem: vscode.StatusBarItem;

    constructor(private tunnelManager: TunnelManager) {
        this.statusBarItem = vscode.window.createStatusBarItem(
            vscode.StatusBarAlignment.Right,
            100
        );

        this.statusBarItem.command = 'nlag.listTunnels';
        this.update();

        const config = vscode.workspace.getConfiguration('nlag');
        if (config.get('showStatusBarItem')) {
            this.statusBarItem.show();
        }
    }

    dispose(): void {
        this.statusBarItem.dispose();
    }

    update(): void {
        const tunnels = this.tunnelManager.getTunnels();
        const count = tunnels.length;

        if (count === 0) {
            this.statusBarItem.text = '$(plug) NLAG';
            this.statusBarItem.tooltip = 'No active tunnels';
        } else {
            this.statusBarItem.text = `$(plug) NLAG: ${count}`;
            this.statusBarItem.tooltip = new vscode.MarkdownString(
                tunnels
                    .map((t) => `- **${t.publicUrl}** → localhost:${t.localPort}`)
                    .join('\n')
            );
        }

        const config = vscode.workspace.getConfiguration('nlag');
        if (config.get('showStatusBarItem')) {
            this.statusBarItem.show();
        } else {
            this.statusBarItem.hide();
        }
    }
}
