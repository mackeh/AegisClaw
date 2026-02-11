import * as http from 'http';
import * as https from 'https';

export class AegisClawClient {
    constructor(private baseUrl: string) {}

    async get(path: string): Promise<any> {
        return this.request('GET', path);
    }

    async post(path: string, body?: any): Promise<any> {
        return this.request('POST', path, body);
    }

    private request(method: string, path: string, body?: any): Promise<any> {
        return new Promise((resolve, reject) => {
            const url = new URL(path, this.baseUrl);
            const mod = url.protocol === 'https:' ? https : http;

            const options = {
                hostname: url.hostname,
                port: url.port,
                path: url.pathname,
                method,
                headers: { 'Content-Type': 'application/json' },
                timeout: 5000,
            };

            const req = mod.request(options, (res) => {
                let data = '';
                res.on('data', (chunk) => { data += chunk; });
                res.on('end', () => {
                    try {
                        resolve(JSON.parse(data));
                    } catch {
                        resolve({ raw: data });
                    }
                });
            });

            req.on('error', (err) => {
                reject(err);
            });

            req.on('timeout', () => {
                req.destroy();
                reject(new Error('Request timeout'));
            });

            if (body) {
                req.write(JSON.stringify(body));
            }
            req.end();
        });
    }
}
