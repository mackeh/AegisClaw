# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is AegisClaw

AegisClaw is a Go-based secure runtime for AI agents. It wraps agent "skills" (containerized commands) in a security envelope: OPA policy evaluation, human-in-the-loop TUI approval, Docker/gVisor sandboxing, age-encrypted secrets, network egress filtering, and tamper-evident audit logging.

## Build & Development Commands

```bash
# Build
go build -o aegisclaw ./cmd/aegisclaw

# Run all tests
go test -v ./...

# Run a single package's tests
go test -v ./internal/policy

# Lint
golangci-lint run

# Initialize runtime config (~/.aegisclaw/)
./aegisclaw init

# Start web dashboard + REST API
./aegisclaw serve --port 8080
```

Requires Go 1.24+ and Docker (for sandbox execution).

## Architecture

### Execution Flow

When a skill runs, the path through the codebase is:

1. **CLI** (`cmd/aegisclaw/main.go`) — Cobra command tree, REPL in `run`, REST API in `serve`
2. **Agent** (`internal/agent/`) — Orchestrator: validates command, evaluates policy, handles approval, injects secrets, runs sandbox, streams output through redactor, logs to audit
3. **Policy** (`internal/policy/`) — OPA/Rego engine. Evaluates scope requests → returns `Allow`, `Deny`, or `RequireApproval`
4. **Approval** (`internal/approval/`) — Bubbletea TUI for interactive approve/deny/always-approve prompts
5. **Sandbox** (`internal/sandbox/`) — Docker executor with hardened defaults (all caps dropped, read-only rootfs, 512MB mem, 1 CPU, 100 pids, no-new-privileges). Pluggable runtime: Docker, gVisor, Kata, Firecracker. `ComposeExecutor` for multi-container skills
6. **Proxy** (`internal/proxy/`) — HTTP/CONNECT egress proxy enforcing domain allowlists
7. **Redactor** (`internal/security/redactor/`) — Wraps io.Writer to scrub secrets from output in real-time
8. **Audit** (`internal/audit/`) — Append-only JSON log with SHA256 hash chain. `Verify()` checks integrity

### Key Supporting Packages

- **Scope** (`internal/scope/`) — Capability model with risk levels (Low/Medium/High/Critical). Parses `scope.name:resource` format
- **Secrets** (`internal/secrets/`) — age encryption (X25519) + `Store` interface. `VaultStore` for HashiCorp Vault KV v2
- **Config** (`internal/config/`) — YAML config from `~/.aegisclaw/config.yaml`. Includes notification and auth config sections
- **Skill** (`internal/skill/`) — YAML manifests defining image, commands, scopes. Supports `platform: docker-compose` with per-service scopes. Ed25519 signature verification. Registry client for search/install
- **Server** (`internal/server/`) — REST API + embedded web dashboard with SSE streaming and WebSocket hub (`/api/ws`). Endpoints under `/api/`
- **Auth** (`internal/server/auth.go`) — RBAC middleware (admin/operator/viewer) with constant-time token comparison
- **Notifications** (`internal/notifications/`) — Webhook (HMAC-SHA256) and Slack notifiers with event-based dispatch
- **Doctor** (`internal/doctor/`) — Health checks: OpenClaw adapter config/connectivity + API secret presence, Docker, gVisor, config, policy, secrets, audit, disk space
- **Profiling** (`internal/profiling/`) — Behaviour profiling with learn/enforce modes. Detects anomalies in network targets, file access, memory, CPU
- **Posture** (`internal/posture/`) — Security posture scoring (A–F grade) across sandboxing, secrets, policy, audit, network
- **Simulate** (`internal/simulate/`) — Dry-run skill analysis: scope evaluation, risk assessment, policy check without execution
- **Guardrails** (`internal/guardrails/`) — LLM prompt safety: injection detection, jailbreak prevention, secret leak sanitization
- **X-Ray** (`internal/xray/`) — Deep runtime inspection of Docker containers: CPU, memory, network I/O, process list
- **Marketplace** (`internal/marketplace/`) — Skill marketplace with ratings, security badges, search, and local index caching
- **MCP** (`internal/mcp/`) — Model Context Protocol stdio server exposing AegisClaw tools to AI assistants
- **System** (`internal/system/`) — Global lockdown state (mutex-protected bool)
- **Telemetry** (`internal/telemetry/`) — OpenTelemetry tracing + Prometheus metrics
- **VS Code Extension** (`vscode-extension/`) — TypeScript extension with status sidebar, audit stream, skills tree, and Rego snippets
- **eBPF** (`internal/ebpf/`) — Kernel-level runtime monitoring: syscall, network, file, and process event types with Monitor lifecycle. Linux-only probe loading
- **Cluster** (`internal/cluster/`) — Multi-node orchestration via gRPC: leader/follower roles, peer registration, audit forwarding, policy sync

### Skill Manifests

Skills are defined in `skill.yaml` files (see `skills/` for examples):
```yaml
name: hello-world
version: "1.0.0"
image: "alpine:latest"
scopes:
  - "files.read:/tmp"
commands:
  hello:
    args: ["echo", "Hello from AegisClaw!"]
```

Skills load from both `~/.aegisclaw/skills/` and a local `./skills/` directory. See `examples/skills/` for starter packs (file-organiser, code-runner, git-stats).

## Conventions

- All core logic lives in `internal/` — nothing is exported as a public Go API
- Default-deny security posture: network egress blocked, all container capabilities dropped, approval required unless policy explicitly allows
- Thread safety via mutexes on shared state (audit logger, system lockdown, redactor)
- CLI output uses emoji prefixes for visual feedback
- Policy files are OPA Rego with package `aegisclaw.policy`
- Version is hardcoded in `cmd/aegisclaw/main.go` (`var version`) and `internal/mcp/server.go`
- Test coverage spans 26 packages; only `agent`, `approval`, `server/ui` lack tests (agent requires Docker, approval is TUI-interactive, ui is an embed directive)
