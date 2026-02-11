import * as vscode from 'vscode';
import { AegisClawClient } from './client';

export class StatusProvider implements vscode.TreeDataProvider<StatusItem> {
    private _onDidChangeTreeData = new vscode.EventEmitter<StatusItem | undefined>();
    readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

    constructor(private client: AegisClawClient) {}

    refresh(): void {
        this._onDidChangeTreeData.fire(undefined);
    }

    getTreeItem(element: StatusItem): vscode.TreeItem {
        return element;
    }

    async getChildren(): Promise<StatusItem[]> {
        try {
            const status = await this.client.get('/api/system/status');
            const systemStatus = status.status === 'lockdown' ? 'LOCKDOWN' : 'Active';
            const icon = status.status === 'lockdown' ? '$(error)' : '$(check)';

            return [
                new StatusItem(`${icon} System: ${systemStatus}`, ''),
                new StatusItem('$(server) Server: Connected', ''),
            ];
        } catch {
            return [
                new StatusItem('$(warning) Server: Disconnected', 'Cannot reach AegisClaw API'),
            ];
        }
    }
}

class StatusItem extends vscode.TreeItem {
    constructor(label: string, tooltip: string) {
        super(label, vscode.TreeItemCollapsibleState.None);
        this.tooltip = tooltip;
    }
}
