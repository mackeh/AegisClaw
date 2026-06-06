# Changelog

All notable changes to AegisClaw are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.10.0] - 2026-06-06 — Agent Harness Control Plane

This release reframes AegisClaw from a skill executor into an inline **control
plane that governs a whole running agent** (OpenClaw, Hermes, or any other),
brokering all four of its action paths — tools, model, network, and host —
behind one default-deny policy and one tamper-evident audit chain. See
[`aegisclaw-harness-architecture.md`](aegisclaw-harness-architecture.md).

### Added

- **Agent harness control plane** (`internal/harness/`): wraps a *whole running
  agent* (OpenClaw, Hermes, or any other) in the AegisClaw envelope, not just
  skills AegisClaw launches itself. Introduces the pluggable `AgentAdapter`
  interface + `Registry`, a `Supervisor` that forces a filtering egress proxy
  and scoped, ephemeral secret injection onto the agent and records the full
  lifecycle to the hash-chained audit log, and a `Launcher` seam. Design doc:
  `aegisclaw-harness-architecture.md`.
- **`aegisclaw harness run` / `harness list`**: launch an agent in the envelope.
  By default the agent runs as a host subprocess pointed at the egress proxy via
  `HTTP(S)_PROXY`; `--image` runs it **inside a hardened sandbox container**
  (read-only rootfs, all caps dropped, no-new-privileges, resource limits), with
  `--runtime gvisor` for stronger isolation.
- **`generic` agent adapter** (`internal/harness/adapters/generic`): runs any
  agent that honours standard proxy/endpoint environment variables — the harness
  is not limited to OpenClaw and Hermes.
- **First-class OpenClaw and Hermes adapters** (`internal/harness/adapters/
  {openclaw,hermes}`): each declares its scoped secrets, a default egress
  allowlist for its endpoints (merged into the proxy allowlist by the
  supervisor), and its ingress surface. OpenClaw declares its messaging channels
  as ingress and reuses the existing `internal/openclaw` health probe; Hermes
  declares its self-generated-skills directory and implements a new optional
  `SandboxRequirer` interface so the supervisor warns when this code-executing
  agent is launched on the host instead of inside the sandbox. Adapters also
  contribute a default egress allowlist via the new `AgentAdapter.
  DefaultEgressDomains` method.
- **Detached sandbox execution** (`sandbox.DockerExecutor.Start` + `Process`):
  long-lived containers with live log streaming and ctx-driven termination,
  reusing the existing hardened container configuration (refactored into a shared
  `hardenedConfigs` helper). Backs `internal/harness/sandboxlauncher`.
- **MCP gateway** (`mcp.Gateway` + `mcp.StdioDownstream`): an inline Model
  Context Protocol proxy between an agent and a real downstream MCP server. Every
  `tools/call` is checked through a pipeline — rate limit → scope→policy
  decision → persistent approval → argument guardrail scan → forward → response
  guardrail scan → hash-chained audit (`audit/mcp.log`) — before it can reach the
  downstream. Reuses `policy`, `guardrails`, `scope`, and the existing rate
  limiter. CLI: `aegisclaw gateway mcp -- <server cmd…>`.
- **MCP tool-description pinning** (`mcp.PinStore`): `tools/list` hash-pins each
  tool's name, description, and input schema (trust-on-first-use). A tool whose
  fingerprint changes after first approval is quarantined and its calls blocked
  until an operator re-approves it via `aegisclaw gateway pins reset` — a defense
  against tool-poisoning / rug-pull attacks.
- **LLM proxy** (`internal/llmproxy`): an OpenAI/Anthropic-compatible reverse
  proxy between an agent and its model provider. Scans prompts and responses with
  the guardrails engine, scrubs known secrets from responses, enforces
  per-session token / cost / request budgets, detects runaway self-prompting
  loops (the same request repeated in a short window), and records every call
  (model, token counts, cost, decision) to the audit log. Standalone via
  `aegisclaw gateway llm --upstream …`, and wired into the harness model plane
  via `aegisclaw harness run --llm-upstream …` (which points the agent's
  `OPENAI_BASE_URL` / `ANTHROPIC_BASE_URL` at the proxy). Closes the agentic-loop
  & cost-guard roadmap item.

- **Agent Control Plane dashboard view** (`GET /api/harness`): reports the four
  enforcement planes (tools, model, network, host) with activity derived from the
  audit and MCP logs (`harness.SummarizeAudit`), plus the registered adapters and
  their declared risk surface. The web dashboard renders this as an "Agent
  Control Plane" panel. A single source of truth for the built-in adapters now
  lives in `internal/harness/adapters` (used by both the CLI and the server).

### Notes

- Secret values resolved for an agent are injected only into the process
  environment for its lifetime; they are never written to disk or the audit log.
- Egress is *forced through* the proxy; default-deny tightening of an empty
  allowlist is tracked with the dedicated egress plane (see roadmap).

## [0.9.0] - 2026-05-20

### Added

- **Evasion-resistant guardrails**: prompt-injection and jailbreak detection now
  runs against normalised text variants, defeating common obfuscation tricks —
  zero-width / invisible characters, Unicode homoglyphs (Cyrillic/Greek
  look-alikes), fullwidth characters, base64/hex-encoded payloads, and
  full-phrase letter-spacing (`internal/guardrails/normalize.go`).
- **Indirect prompt injection detection**: new `Engine.CheckData(source, text)`
  scans untrusted content the agent ingests — fetched web pages, tool outputs,
  retrieved documents, file contents — for instructions that try to hijack the
  agent. Detects forged conversation/role delimiters (`<system>`, ChatML
  markers), AI-addressed override directives, HTML-comment payloads, and
  exfiltration directives (`internal/guardrails/indirect.go`).
- **`guardrails check`/`scan --mode data`**: new CLI mode with a `--source`
  label for scanning untrusted data through the indirect-injection rails.
- **Guardrail pipeline integration**: the agent now scans every skill's output
  with the indirect-injection rails before it is returned, so poisoned data
  cannot silently re-enter an agent's model context. Configurable via the new
  `guardrails.mode` config key (`off` / `warn` / `block`, default `warn`);
  violations are written to the audit log as `guardrail.violation` entries
  (`internal/agent/guardrails.go`).
- **`aegisclaw-threat-cases.md`**: reference threat-case document mapping
  real-world autonomous-agent vulnerability classes — illustrated by the Hermes
  agent (unauthenticated RCE, scanner bypass, symlink traversal CVE-2026-7397,
  credential exposure CVE-2026-22798) — to the AegisClaw controls that contain
  each class. Linked from `README.md`, `SECURITY.md`, and the roadmap.
- **Network-exposure safeguard for `aegisclaw serve`**: a new `--host` flag
  controls the bind address (default `127.0.0.1`). A non-loopback bind is
  refused unless API-token authentication is configured, or `--insecure` is
  passed — closing the unauthenticated-RCE class by default
  (`internal/server/bind.go`).
- **API authentication wired in**: the previously dormant RBAC `AuthMiddleware`
  now guards every API endpoint, gated by `~/.aegisclaw/auth.yaml`
  (`enabled` + `keys`). Endpoints are scoped by role — viewer (read-only),
  operator (actions), admin (lockdown/unlock). With no auth file present,
  behaviour is unchanged (loopback-only, pass-through).
- **MCP server hardening**: tool calls are now rate-limited (sliding window,
  default 120/min, `--rate-limit` flag) and recorded to a dedicated
  tamper-evident audit log at `~/.aegisclaw/audit/mcp.log` — kept separate
  from the main chain so the two processes never corrupt each other's hash
  chain. Added tool-name and audit-query-limit input validation
  (`internal/mcp/ratelimit.go`).
- Expanded direct injection and jailbreak pattern sets (system-prompt
  exfiltration, role confusion, `god/admin/debug` mode, hypothetical-framing
  jailbreaks).

### Changed

- Guardrail violations report when a match was found only after
  de-obfuscation, so operators can see evasion attempts.
- `Result` gained a `Source` field carrying the origin label for data checks.
- **Version bump**: `0.8.0` → `0.9.0` across CLI, MCP server, and VS Code extension.
- Updated README, roadmap, SECURITY.md, and CLAUDE.md for v0.9.0.

## [0.8.0] - 2026-03-25

### Removed

- **`internal/notifications/`**: Unused notification dispatcher, webhook notifier, and Slack notifier — never integrated into the runtime.
- **`internal/profiling/`**: Unused behaviour profiling package — never wired into the agent execution path.
- **eBPF global singleton**: Removed `SetGlobal()` / `GetGlobal()` and associated module-level state from `internal/ebpf/monitor.go` — never called.
- **`NotificationConfig`**: Removed dead notification config type and field from `internal/config/`.
- **`AegisClaw_PROJECT_updated.md`**: Stale early-stage planning document superseded by README and roadmap.
- **MCP `io` import hack**: Removed unused `var _ io.Reader` and corresponding import from `internal/mcp/server.go`.

### Fixed

- **MCP server version**: Corrected hardcoded version from `0.5.1` to `0.8.0` in the MCP `initialize` response.

### Changed

- **Version bump**: `0.7.1` → `0.8.0` across CLI, MCP server, and VS Code extension.
- **SECURITY.md**: Updated supported versions to 0.7.x and 0.8.x.
- **CONTRIBUTING.md**: Updated Go prerequisite from 1.22+ to 1.24+ (matches `go.mod`).
- **GEMINI.md**: Updated Go prerequisite from 1.22+ to 1.24+.
- **CLAUDE.md**: Removed references to deleted `notifications` and `profiling` packages; updated test coverage count.
- **README.md**: Added v0.8.0 cleanup milestone to roadmap.
- **Roadmap**: Updated last-modified date; added v0.8.0 entry; renumbered future phases.

## [0.7.1] - 2026-02-xx

### Fixed

- Hardened skill manifest file access with `OpenRoot`.
- Resolved code scanning path injection alerts.
- Prevented eBPF release build failures on Linux arm64.

### Added

- OpenClaw health details in dashboard.

## [0.7.0] - 2026-01-xx

### Added

- Multi-node cluster orchestration (leader/follower, gRPC, audit forwarding, policy sync).
- eBPF runtime monitoring (syscall, network, file, process tracing on Linux x86).

## [0.6.0]

### Added

- Live threat map dashboard with WebSocket hub.
- Agent X-Ray mode (container deep inspection).
- Security posture score (A-F grading).
- MCP server (stdio transport for AI assistants).
- Skill marketplace with ratings and security badges.
- VS Code extension (status, audit, skills, Rego snippets).
- `aegisclaw simulate` dry-run mode.

## [0.5.0]

### Added

- Kata Containers / Firecracker MicroVM support.
- Pluggable vault backends (HashiCorp Vault KV v2).
- LLM guardrails (injection detection, jailbreak prevention).
- RBAC auth (admin/operator/viewer) with API token auth.

## [0.4.0]

### Added

- Cross-platform install script and GoReleaser builds.
- Interactive init wizard with environment detection.
- Starter skill packs (file-organiser, code-runner, git-stats).
- `aegisclaw doctor` health diagnostics.
- Docker Compose multi-container skills.
- Policy templates (strict/standard/permissive) and shell completions.

## [0.3.0]

### Added

- Modern web dashboard (dark mode, SOC view).
- Real-time terminal streaming.
- Prometheus metrics and OpenTelemetry tracing.
- Active secret redaction.
- Emergency lockdown (panic button).

## [0.2.0]

### Added

- OPA (Rego) policy engine.
- gVisor sandbox runtime support.

## [0.1.0]

### Added

- CLI (`init`, `run`, `logs`, `policy`, `secrets`, `sandbox`).
- Hardened Docker sandbox.
- TUI-based human-in-the-loop approval.
- `age`-based secret encryption.
- Hash-chained audit logging.
- OpenClaw adapter and egress proxy.
- Ed25519 skill signature verification.
