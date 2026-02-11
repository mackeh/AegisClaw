import * as vscode from 'vscode';
import { AegisClawClient } from './client';

export class SkillsProvider implements vscode.TreeDataProvider<SkillItem> {
    private _onDidChangeTreeData = new vscode.EventEmitter<SkillItem | undefined>();
    readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

    constructor(private client: AegisClawClient) {}

    refresh(): void {
        this._onDidChangeTreeData.fire(undefined);
    }

    getTreeItem(element: SkillItem): vscode.TreeItem {
        return element;
    }

    async getChildren(): Promise<SkillItem[]> {
        try {
            const skills = await this.client.get('/api/skills');
            if (!Array.isArray(skills) || skills.length === 0) {
                return [new SkillItem('No skills installed', '')];
            }

            return skills.map((s: any) => {
                const label = `$(package) ${s.name} v${s.version || '?'}`;
                const scopes = (s.scopes || []).join(', ');
                return new SkillItem(label, `Scopes: ${scopes}`);
            });
        } catch {
            return [new SkillItem('$(warning) Cannot load skills', '')];
        }
    }
}

class SkillItem extends vscode.TreeItem {
    constructor(label: string, tooltip: string) {
        super(label, vscode.TreeItemCollapsibleState.None);
        this.tooltip = tooltip;
    }
}
