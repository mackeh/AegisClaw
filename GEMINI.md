# AegisClaw - Secure Agent Runtime

AegisClaw is a **secure-by-default runtime** and security envelope for OpenClaw-style personal AI agents. It mitigates risks like prompt injection, secrets leakage, and over-permissioned tools by providing a hardened execution boundary.

## 🛡️ Design Principles

1.  **Secure by Default**: No exposed ports, no plaintext secrets, and non-root execution out-of-the-box.
2.  **Least Privilege**: Capability-based access (scopes) where every tool request must declare its requirements.
3.  **Defense in Depth**: Combines guardrails, policy engines, sandboxing, and signed artifacts.
4.  **Reproducible & Auditable**: Focus on SBOMs, attestations, and tamper-evident logging.
5.  **Human-in-the-Loop**: Mandatory approvals for high-risk actions (e.g., payments, shell execution).

## 🏗️ Architecture

-   **Policy Engine**: Evaluates scope requests against local rules.
-   **Sandbox Executor**: Hardened Docker (with future gVisor/Firecracker support).
-   **Secret Broker**: Injects short-lived, scoped credentials using `age` encryption.
-   **Audit Log**: Hash-chained, tamper-evident record of all actions.
-   **Context Firewall**: (Planned) Blocks untrusted input from modifying system/tool policy.

## ☣️ Threat Model (v1)

AegisClaw is specifically designed to defend against:
-   **Prompt Injection** via untrusted inbound content.
-   **Malicious Skills** (supply-chain attacks).
-   **Secrets Leakage** in logs or prompts.
-   **Lateral Movement** from the sandbox to the host OS.

## 🛠️ Building and Running

### Prerequisites
- Go 1.22+
- Docker

### Key Commands
-   **Build**: `go build -o aegisclaw ./cmd/aegisclaw`
-   **Init**: `./aegisclaw init` (creates `~/.aegisclaw` structure)
-   **Sandbox Test**: `./aegisclaw sandbox run-sandbox alpine:latest echo "Hello Safe World"`
-   **Secrets**: `./aegisclaw secrets init` followed by `set` commands.
-   **Audit**: `./aegisclaw logs verify` to check cryptographic integrity.

## 📜 Development Conventions

-   **Internal-First**: Core logic resides in `internal/` to prevent external dependency bloat and enforce encapsulation.
-   **Restrictive Defaults**: Always default to `deny` or `RequireApproval`.
-   **Immutability**: Audit logs are append-only; sandbox filesystems are read-only by default.

## 🗺️ Roadmap

### v0.1.x (Foundations)
- [x] CLI (init/run/logs/policy)
- [x] Hardened Docker sandbox
- [x] Scope model & TUI approval UI
- [x] `age` secret management
- [x] Hash-chained audit logging

### v0.2.x (Policy & Runtimes)
- [x] OPA policy engine integration
- [x] Cosign signature verification for skills
- [x] gVisor/runsc support via `sandbox_runtime`

### v0.3.x (Observability & UX)
- [x] Modern Web Dashboard
- [x] Real-time Terminal Streaming
- [x] Prometheus Metrics & OpenTelemetry Tracing
- [x] Active Secret Redaction
- [x] Emergency Lockdown (Panic Button)

### v0.4.x (Usability & Developer Experience)
- [x] Package manager distribution (install script, goreleaser with Windows builds)
- [x] Interactive init wizard with environment detection
- [x] Starter skill packs (file-organiser, code-runner, git-stats)
- [x] `aegisclaw doctor` health check command
- [x] Docker-Compose multi-container skill orchestration
- [x] Notification system (webhooks, Slack)
- [x] Policy templates (strict/standard/permissive) & shell completions

### v0.5.x (Advanced Security)
- [x] Kata Containers / Firecracker MicroVM support (pluggable runtime interface)
- [x] Pluggable vault backends (HashiCorp Vault KV v2 with Store interface)
- [x] LLM guardrails (prompt injection, jailbreak, secret leak detection)
- [x] Runtime behaviour profiling & anomaly detection
- [x] Auth & access control (RBAC roles, API token auth)

### v0.6.x (Ecosystem)
- [x] Live threat map dashboard with WebSocket streaming
- [x] Agent X-Ray mode (deep runtime inspection via Docker API)
- [x] Security posture score & badge (A–F grading)
- [x] MCP server for AI assistant integration (stdio transport)
- [x] Skill marketplace with ratings and security badges
- [x] VS Code extension (status, audit, skills, Rego snippets)
- [x] `aegisclaw simulate` dry-run mode