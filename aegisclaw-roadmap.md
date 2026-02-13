# AegisClaw Roadmap

> Last updated: February 2026

---

## Completed Phases

### ✅ v0.1.x — Foundations (Complete)

- Go-based CLI (`aegisclaw init`, `secrets`, `sandbox`, `logs`)
- Policy engine with granular scopes (`files.read`, `shell.exec`, `net.outbound`)
- TUI-based human-in-the-loop approval for high-risk actions
- Hardened Docker sandbox (non-root, read-only rootfs, dropped capabilities, seccomp)
- `age`-based secret encryption for API keys
- Tamper-evident, hash-chained audit logging
- OpenClaw adapter for agent runtime integration
- Egress proxy for network control
- Signed skill verification (ed25519)

### ✅ v0.2.x — Policy & Runtimes (Complete)

- OPA (Rego) policy engine integration
- gVisor (`sandbox_runtime`) support for stronger isolation
- Skill manifest format (`skills/*.yaml`) with scope declarations
- Adapter health monitoring and connection status

### ✅ v0.3.x — Observability & UX (Complete)

- Modern web dashboard (dark mode, Security Operations Center view)
- Real-time terminal streaming with live log output
- Prometheus metrics endpoint
- OpenTelemetry tracing
- Active secret redaction in logs and console output
- Emergency lockdown / panic button
- Security envelope visualisation (sandbox status indicator)
- Explainable audit tooltips (why an action was allowed/denied)
- Skill store with remote registry browsing and one-click install

### ✅ v0.4.x — Usability & Developer Experience (Complete)

#### Installation & Onboarding

- **Package manager distribution**: `brew install aegisclaw`, `go install`, pre-built binaries via GoReleaser for Linux/macOS/Windows (amd64 + arm64)
- **Interactive `init` wizard**: Guided setup that detects Docker/gVisor availability, configures default policies, and walks through first secret and skill registration
- **Starter skill packs**: Curated bundles of safe, pre-signed skills (file organiser, web search, code runner) so users have something useful immediately after install
- **`aegisclaw doctor`**: Diagnostic command that checks Docker, gVisor, secrets, adapter connectivity, and policy health in one go — outputs a clear pass/fail checklist

#### Day-to-Day Workflow

- **`docker-compose` skill orchestration**: Support multi-container skills (e.g., agent + database + cache) with coordinated sandboxing and shared network policies
- **Policy templates**: Pre-built Rego policy profiles — `strict` (deny-by-default, approve everything), `standard` (allow known-safe, approve high-risk), `permissive` (allow most, log everything) — selectable during init
- **Scope autosuggestion**: When a skill requests scopes beyond its manifest, suggest the minimal scopes needed based on observed behaviour rather than requiring manual YAML editing
- **Dashboard mobile responsiveness**: Responsive web UI for monitoring agent activity from a phone or tablet
- **Notification system**: Webhook, Slack, and email notifications for pending approvals, denied actions, and emergency lockdowns

#### CLI Enhancements

- **`aegisclaw replay <log-id>`**: Replay an audit log entry in dry-run mode to understand what happened and what would happen if re-executed
- **`aegisclaw diff <policy-a> <policy-b>`**: Compare two Rego policies side-by-side with highlighted permission differences
- **Shell completions**: Bash, Zsh, Fish, and PowerShell autocompletions generated from CLI metadata

### ✅ v0.5.x — Advanced Security (Complete)

#### Runtime Hardening

- **Kata Containers / Firecracker support**: MicroVM-based isolation for workloads that need stronger-than-Docker boundaries
- **Nix/bubblewrap sandbox**: Lightweight, non-Docker sandbox option for environments where Docker isn't available or desired
- **Runtime behaviour profiling**: Learn normal syscall and network patterns per skill, flag anomalies in real-time (e.g., a file-organiser skill suddenly making network requests)
- **Resource quotas**: CPU, memory, disk I/O, and network bandwidth limits per skill — prevent runaway agents from consuming host resources

#### Secret Management

- **`sops` integration**: Support Mozilla SOPS-encrypted files alongside `age`
- **Pluggable vault backends**: HashiCorp Vault, Infisical, Bitwarden, and AWS Secrets Manager as secret sources — secrets are never written to disk unencrypted
- **Secret rotation**: Automatic key rotation with configurable schedules and notification when skills need re-authentication
- **Ephemeral secrets**: Short-lived credentials injected into sandboxes that auto-expire after execution

#### LLM Safety

- **NeMo Guardrails integration**: LLM prompt protection layer — detect and block prompt injection, jailbreaks, and off-topic steering before prompts reach the model
- **Prompt/response audit trail**: Log every LLM interaction (prompt + response) with optional PII redaction, creating a full chain of accountability for agent decisions
- **Token budget enforcement**: Per-skill and per-session token limits to prevent cost runaway from agent loops
- **Output content filtering**: Configurable filters that flag or block agent outputs containing sensitive data, harmful content, or policy violations

#### Auth & Access Control

- **Tailscale/WireGuard integration**: Private mesh networking so the dashboard and API are only accessible over encrypted tunnels
- **Authelia/Keycloak SSO**: Web UI identity provider integration for team deployments — RBAC with admin, operator, and viewer roles
- **mTLS for adapter communication**: Mutual TLS between AegisClaw and OpenClaw endpoints to prevent man-in-the-middle attacks
- **API key scoping**: Per-key permissions so different integrations (CI, dashboard, CLI) have minimal required access

### ✅ v0.6.x — Woo Factor & Ecosystem (Complete)

#### Visual & Interactive

- **Live threat map**: Real-time animated dashboard view showing agent actions as they happen — skill executions pulse, denied actions flash red, approvals glow green — a "mission control" feel for your AI agents
- **"Agent X-Ray" mode**: Click any running skill to see a live breakdown: active syscalls, open file handles, network connections, memory usage, and current scope consumption — full transparency into what the agent is actually doing inside the sandbox
- **Security posture score**: Embeddable badge and dashboard widget (`AegisClaw: A+`) scoring your configuration across sandboxing, secret management, policy strictness, and audit integrity — gamification that rewards good security hygiene
- **Approval UX overhaul**: Rich approval cards (web + Slack + mobile push) showing exactly what the agent wants to do, with context (which skill, what scope, risk level), diff of proposed changes, and one-tap approve/deny

#### Skills Ecosystem

- **Git-based skill distribution**: `aegisclaw skill install github.com/org/skill` — pull skills directly from Git repos with hash-chained provenance verification
- **Skill marketplace**: Community registry with ratings, verified publishers, security audit badges, and automated vulnerability scanning of skill images
- **Skill sandboxing profiles**: Per-skill seccomp and AppArmor profiles auto-generated from observed behaviour during a "learning" phase, then locked down for production
- **Skill composition**: Chain multiple skills into workflows with data passing between sandbox boundaries — each step isolated, full audit trail across the pipeline

#### Developer Experience

- **VS Code extension**: Sidebar panel showing AegisClaw status, live audit stream, one-click approvals, and Rego policy linting with inline diagnostics
- **`aegisclaw simulate`**: Dry-run mode that predicts what a skill would do (file access, network calls, resource usage) without actually executing it — like a flight simulator for agent actions
- **Policy playground**: Browser-based Rego editor with live evaluation against sample skill manifests and audit scenarios — test policies before deploying them
- **Terraform/Pulumi provider**: Infrastructure-as-code resources for provisioning AegisClaw instances, policies, and skill registries in team/org deployments

#### Integrations

- **MCP (Model Context Protocol) server**: Expose AegisClaw as an MCP tool server so any MCP-compatible AI assistant can run sandboxed skills through AegisClaw's security envelope
- **GitHub Actions integration**: `aegisclaw/action@v1` that runs skills in CI with the same sandbox guarantees as local execution — consistent security in dev and CI
- **Webhook-driven automation**: IFTTT-style triggers — "when a skill is denied 3 times, notify the team and auto-escalate to admin"

---

### ✅ v0.7.x — Multi-node Orchestration (Complete)

- **Cluster mode**: Distributed agent orchestration with leader/follower roles
- **Centralized policy distribution**: Push Rego policies from leader to all nodes
- **Audit aggregation**: Stream audit logs from follower nodes to a central leader for unified SOC view
- **Node health monitoring**: Real-time status and uptime tracking for cluster members
- **Enhanced `aegisclaw doctor`**: OpenClaw adapter diagnostics now validate config syntax, endpoint reachability, and referenced API secret presence

---

## Upcoming Phases

### 🔭 v0.8.x — Advanced Security & Compliance (Q4 2026)

- **Federated skill trust**: Cross-organisation skill sharing with cryptographic trust chains
- **Compliance frameworks**: Pre-built policy packs for SOC 2, HIPAA, and GDPR
- **AI-powered policy generation**: Automated minimal-scope suggestion via LLM analysis
- **AegisClaw Cloud**: Managed SaaS offering for teams

---

## How to Contribute

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

**High-impact areas right now:**

- 🧪 Security testing and fuzzing of the sandbox boundary
- 📚 Documentation improvements and tutorials
- 🔨 Implementing eBPF probes for Linux (`internal/ebpf`)

Report bugs or request features via [GitHub Issues](https://github.com/mackeh/AegisClaw/issues).
