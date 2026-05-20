# AegisClaw Roadmap

> Last updated: May 2026

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
- **Live OpenClaw health API + dashboard wiring**: `GET /api/openclaw/health` now powers adapter status and latency indicators in the web UI

---

## Upcoming Phases

### ✅ v0.8.0 — Codebase Cleanup (Complete)

- Removed unused `notifications` and `profiling` packages
- Removed dead eBPF global singleton functions
- Cleaned up stale MCP server version and unused imports
- Updated all documentation and Go version requirements
- Removed stale planning documents

### ✅ v0.9.0 — Guardrails 2.0 (Complete)

The first slice of the v0.9.x threat-hardening work (see Threat Landscape below):

- **Evasion-resistant detection**: prompt-injection and jailbreak rules now run
  against normalised text variants. Defeats obfuscation via Unicode homoglyphs
  (Cyrillic/Greek look-alikes), zero-width / invisible characters, fullwidth
  characters, base64/hex-encoded payloads, and full-phrase letter-spacing.
- **Indirect prompt injection detection**: new `Engine.CheckData(source, text)`
  scans untrusted content the agent *ingests* — fetched web pages, tool
  outputs, retrieved documents, file contents — for hijack attempts: forged
  conversation/role delimiters (`<system>`, ChatML markers), AI-addressed
  override directives, HTML-comment payloads, and exfiltration instructions.
- **CLI `guardrails check/scan --mode data`** with a `--source` origin label.
- **Expanded pattern sets** for direct injection and jailbreaks (system-prompt
  exfiltration, role confusion, privilege-mode jailbreaks, hypothetical framing).
- **Guardrail pipeline integration**: the agent now scans every skill's output
  for indirect prompt injection before returning it, so poisoned data cannot
  silently re-enter an agent's model context. Configurable via `guardrails.mode`
  (`off`/`warn`/`block`, default `warn`); violations are written to the audit
  log. The guardrails engine is no longer CLI-only.

---

## Threat Landscape — Why v0.9.x Focuses on Evolving Agent Threats

AegisClaw's original threat model (v0.1–v0.8) is strong on the *host* boundary:
sandbox isolation, capability dropping, scoped permissions, audit integrity. The
fastest-moving risks for AI agents in 2026, however, target the *cognitive*
boundary — what the model is told to do — and the *supply chain* of tools and
skills. v0.9.x prioritises these:

1. **Indirect prompt injection** — the highest-impact agent threat. Malicious
   instructions are planted in data the agent retrieves (web pages, emails,
   documents, API responses) and hijack the agent without the user ever typing
   them. Addressed by `CheckData` (shipped in v0.9.0).
2. **Obfuscated injection** — attackers bypass naïve keyword filters with
   homoglyphs, zero-width characters, encoding, and letter-spacing. Addressed by
   the normalization layer (shipped in v0.9.0).
3. **Tool poisoning** — an MCP server or skill silently changes a tool's
   description/behaviour after first approval, steering the agent. Mitigation:
   description pinning + hash verification.
4. **Untrusted tool-call surface** — AegisClaw's own MCP server currently
   executes tool calls with no per-call authorization, rate limiting, or audit.
5. **Runaway agentic loops** — self-prompting agents burn cost and take
   unbounded actions. Mitigation: loop detection + token/cost budgets.
6. **Skill supply chain** — skill container images may carry known CVEs;
   signatures prove authorship but not safety. Mitigation: SBOM + image
   vulnerability scanning + a signature transparency log.

### Real-World Motivation

These priorities are not theoretical. Publicly reported incidents in other
autonomous agents — see [`aegisclaw-threat-cases.md`](aegisclaw-threat-cases.md)
for the Hermes agent case study — show the recurring failure modes:
unauthenticated RCE from an exposed control plane, keyword-scanner bypass via
dynamic string construction, symlink/path traversal, and opt-in (off-by-default)
secret redaction. AegisClaw treats each as a *class* to be contained by
defense-in-depth, not patched once. Two gaps that case study surfaced are now
tracked below: a network-exposure safeguard and stricter MCP hardening.

### 🔭 v0.9.x — Remaining Threat-Hardening Work

- **Network-exposure safeguards**: refuse to bind `aegisclaw serve` to a
  non-loopback address unless API-token auth is configured — closing the
  "unauthenticated RCE from a 0.0.0.0 bind" class by default.

- **MCP server hardening**: per-tool authorization, rate limiting, input
  validation, and audit logging for every MCP tool invocation.
- **Tool-poisoning defense**: pin and hash-verify MCP/skill tool descriptions;
  re-prompt for approval when a description changes.
- **Agentic loop & cost guards**: detect self-prompting loops; enforce per-skill
  and per-session token/cost budgets.
- **Skill supply-chain security**: SBOM generation and image vulnerability
  scanning for skills, backed by a signature transparency log.

### 🔭 v0.10.x — Compliance & Federation

- **Compliance frameworks**: pre-built policy packs for SOC 2, HIPAA, and GDPR.
- **Federated skill trust**: cross-organisation skill sharing with cryptographic
  trust chains.
- **AI-powered policy generation**: automated minimal-scope suggestion via LLM
  analysis of observed skill behaviour.
- **AegisClaw Cloud**: managed multi-tenant SaaS offering for teams.

---

## How to Contribute

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

**High-impact areas right now:**

- 🧬 Guardrail pipeline integration into the agent execution path
- 🔐 MCP server hardening (per-tool auth, rate limiting, audit)
- 🧪 Security testing and fuzzing of the sandbox and guardrail boundaries
- 📚 Documentation improvements and tutorials

Report bugs or request features via [GitHub Issues](https://github.com/mackeh/AegisClaw/issues).
