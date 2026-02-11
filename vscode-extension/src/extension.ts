import * as vscode from 'vscode';
import { StatusProvider } from './statusProvider';
import { AuditProvider } from './auditProvider';
import { SkillsProvider } from './skillsProvider';
import { AegisClawClient } from './client';

let refreshInterval: NodeJS.Timeout | undefined;

export function activate(context: vscode.ExtensionContext) {
    const config = vscode.workspace.getConfiguration('aegisclaw');
    const serverUrl = config.get<string>('serverUrl', 'http://127.0.0.1:8080');
    const client = new AegisClawClient(serverUrl);

    const statusProvider = new StatusProvider(client);
    const auditProvider = new AuditProvider(client);
    const skillsProvider = new SkillsProvider(client);

    vscode.window.registerTreeDataProvider('aegisclaw.status', statusProvider);
    vscode.window.registerTreeDataProvider('aegisclaw.audit', auditProvider);
    vscode.window.registerTreeDataProvider('aegisclaw.skills', skillsProvider);

    context.subscriptions.push(
        vscode.commands.registerCommand('aegisclaw.refresh', () => {
            statusProvider.refresh();
            auditProvider.refresh();
            skillsProvider.refresh();
            vscode.window.showInformationMessage('AegisClaw: Refreshed');
        }),
        vscode.commands.registerCommand('aegisclaw.lockdown', async () => {
            const confirm = await vscode.window.showWarningMessage(
                'Trigger emergency lockdown? This will kill all running skills.',
                'Yes', 'No'
            );
            if (confirm === 'Yes') {
                await client.post('/api/system/lockdown');
                statusProvider.refresh();
                vscode.window.showWarningMessage('AegisClaw: EMERGENCY LOCKDOWN ACTIVE');
            }
        }),
        vscode.commands.registerCommand('aegisclaw.unlock', async () => {
            await client.post('/api/system/unlock');
            statusProvider.refresh();
            vscode.window.showInformationMessage('AegisClaw: System unlocked');
        }),
        vscode.commands.registerCommand('aegisclaw.verifyLogs', async () => {
            const result = await client.get('/api/logs/verify');
            if (result.status === 'valid') {
                vscode.window.showInformationMessage('AegisClaw: Audit log integrity verified');
            } else {
                vscode.window.showErrorMessage(`AegisClaw: ${result.message}`);
            }
        })
    );

    // Auto-refresh
    if (config.get<boolean>('autoRefresh', true)) {
        const interval = config.get<number>('refreshInterval', 5000);
        refreshInterval = setInterval(() => {
            statusProvider.refresh();
        }, interval);
    }

    vscode.window.showInformationMessage('AegisClaw extension activated');
}

export function deactivate() {
    if (refreshInterval) {
        clearInterval(refreshInterval);
    }
}
