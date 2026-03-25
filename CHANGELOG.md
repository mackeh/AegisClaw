# Changelog

All notable changes to AegisClaw are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

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
