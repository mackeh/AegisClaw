import * as vscode from 'vscode';
import { AegisClawClient } from './client';

export class AuditProvider implements vscode.TreeDataProvider<AuditItem> {
    private _onDidChangeTreeData = new vscode.EventEmitter<AuditItem | undefined>();
    readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

    constructor(private client: AegisClawClient) {}

    refresh(): void {
        this._onDidChangeTreeData.fire(undefined);
    }

    getTreeItem(element: AuditItem): vscode.TreeItem {
        return element;
    }

    async getChildren(): Promise<AuditItem[]> {
        try {
            const entries = await this.client.get('/api/logs');
            if (!Array.isArray(entries)) {
                return [new AuditItem('No audit entries', '')];
            }

            // Show last 20 entries
            const recent = entries.slice(-20).reverse();
            return recent.map((e: any) => {
                const icon = e.action === 'deny' ? '$(x)' : '$(check)';
                const label = `${icon} ${e.action || 'unknown'} — ${e.skill || 'system'}`;
                return new AuditItem(label, JSON.stringify(e, null, 2));
            });
        } catch {
            return [new AuditItem('$(warning) Cannot load audit log', '')];
        }
    }
}

class AuditItem extends vscode.TreeItem {
    constructor(label: string, tooltip: string) {
        super(label, vscode.TreeItemCollapsibleState.None);
        this.tooltip = tooltip;
    }
}
