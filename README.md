# AegisClaw - Secure Agent Runtime

![AegisClaw Banner](assets/banner.png)

AegisClaw is a **secure-by-default runtime** and security envelope for OpenClaw-style personal AI agents.

![CI](https://github.com/mackeh/AegisClaw/workflows/build/badge.svg)
![Go Version](https://img.shields.io/github/go-mod/go-version/mackeh/AegisClaw)
![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)

> **Goal:** Make "agentic automation" safe enough for individuals by default, and scalable enough for teams.

AegisClaw acts as a security envelope around your AI agents, providing sandboxing, granular permissions, and human-in-the-loop approvals.

---

## 🚀 Key Features

- **🐳 Hardened Sandbox**: Executes agent skills in a restricted Docker container (non-root, read-only rootfs, dropped capabilities, seccomp).
- **🛡️ Granular Scopes**: Permission model (e.g., `files.read:/home/user/docs`, `shell.exec`, `net.outbound:github.com`).
- **👁️ Security Visualization**: Active "Security Envelope" indicator confirming sandbox isolation and protection status.
- **🔌 Adapter Health**: Real-time connection monitoring to the OpenClaw agent runtime.
- **🚫 Active Secret Redaction**: Automatically scrubs secrets from logs and console output if they leak.
- **🛑 Emergency Lockdown**: "PANIC BUTTON" to instantly kill all running skills and block new executions.
- **✋ Human-in-the-Loop**: TUI-based approval system for high-risk actions.
- **🔐 Secret Encryption**: `age`-based encryption for sensitive API keys.
- **📜 Audit Logging**: Tamper-evident, hash-chained logs with explainable decision tooltips.
- **🖥️ Web Dashboard**: Modern, dark-mode GUI for live monitoring and management.

## 🖼️ Gallery

### Dashboard

The V4 Dashboard features a dedicated **Security Operations Center** with:

- **Active Security Envelope**: Visual confirmation of sandbox isolation.
- **OpenClaw Status**: Real-time connection health and latency metrics.
- **Explainable Audits**: Tooltips explaining _why_ an action was allowed or denied.

![Dashboard](assets/dashboard_v4.png)

### Audit Timeline

![Audit Log](assets/audit_log.png)

### Skill Registry

![Skill Store](assets/skill_store.png)

## 📦 Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/mackeh/AegisClaw.git
cd AegisClaw

# Build the binary
go build -o aegisclaw ./cmd/aegisclaw

# Verify installation
./aegisclaw --version
```

## ⚡ Quick Start

### 1. Initialize

Create the default configuration structure in `~/.aegisclaw`:

```bash
./aegisclaw init
```

### 2. Configure Secrets

Initialize the encryption keys and set a secret:

```bash
./aegisclaw secrets init
./aegisclaw secrets set OPENAI_API_KEY sk-proj-12345
```

### 3. Run a Sandboxed Command

Test the hardened runtime using a Docker image:

```bash
# This runs 'echo' inside the sandbox
./aegisclaw sandbox run-sandbox alpine:latest echo "Hello Safe World"
```

### 4. View Audit Logs

Check the immutable log of actions:

```bash
./aegisclaw logs
./aegisclaw logs verify  # Check cryptographic integrity
```

### 5. Multi-node Clusters (v0.7.0+)

AegisClaw supports distributed orchestration with centralized policy and audit:

```bash
# On Leader Node (manages policies and aggregates logs)
./aegisclaw cluster status --role leader --address 10.0.0.1:9090

# On Follower Node (joins the cluster to execute skills)
./aegisclaw cluster join 10.0.0.1:9090 --node-id worker-1
```

## 🖥️ Web GUI Guide

AegisClaw includes a modern web-based dashboard for easy monitoring and management.

### 1. Launch the Dashboard

Start the AegisClaw API and UI server:

```bash
./aegisclaw serve --port 8080
```

Then, open your browser and navigate to `http://localhost:8080`.

### 2. Dashboard Features

- **System Overview**: Monitor system status, total executions, and the active policy mode (OPA/Rego).
- **Skill Management**:
    - **Installed Skills**: View all locally available skills and run them with a single click.
    - **Skill Store**: Search the remote registry for new skills and install them directly from the UI.
- **Live Monitoring**:
    - **Real-time Terminal**: When running a skill, a live terminal pops up showing real-time logs with active secret redaction.
    - **Audit Activity**: View the most recent actions taken by your agents.
- **Security Tools**:
    - **Log Verification**: Click "Verify Integrity" in the audit section to cryptographically prove the logs haven't been tampered with.
    - **Emergency Stop**: The prominent red **EMERGENCY STOP** button instantly kills all running skill containers and locks the runtime.

## 🔗 OpenClaw Integration
This section shows how to integrate OpenClaw agents with AegisClaw while preserving AegisClaw's security guarantees (sandboxing, scoped permissions, audit logging).

Prerequisites

- AegisClaw built and configured (see Quick Start)
- Docker installed and running
- OpenClaw agent or skill package (container image or source)

Steps

1. Store OpenClaw credentials in AegisClaw secrets

```bash
# Store the OpenClaw API key (example)
./aegisclaw secrets set OPENCLAW_API_KEY sk-openclaw-xxxxx
```

2. Enable/configure the OpenClaw adapter

AegisClaw includes an OpenClaw adapter that mediates communication between agents and external services. Enable it by creating an adapter config at `~/.aegisclaw/adapters/openclaw.yaml`:

```yaml
enabled: true
endpoint: "http://localhost:8080" # or the OpenClaw service URL
api_key_secret: "OPENCLAW_API_KEY" # name in aegisclaw secrets
timeout_ms: 5000
```

3. Register your OpenClaw-based skill/agent (manifest)

Create a skill manifest that AegisClaw can run in the sandbox. Example `skills/web-search.yaml`:

```yaml
name: web-search
image: ghcr.io/openclaw/web-search:latest
platform: docker
scopes:
  - net.outbound:api.openclaw.example.com
  - files.read:/tmp/allowed
signature: "ed25519:..." # optional signed skill verification
```

Register the skill with AegisClaw (if you keep skills in a local registry or the config directory):

```bash
# copy manifest into the skills directory used by AegisClaw
mkdir -p ~/.aegisclaw/skills
cp skills/web-search.yaml ~/.aegisclaw/skills/
```

4. Run the skill with AegisClaw's hardened runtime

```bash
# Run a registered skill inside the sandbox (example)
./aegisclaw sandbox run-registered web-search
```

If your deployment runs an external OpenClaw service (instead of containerized skills), ensure AegisClaw's adapter will only allow the necessary egress and that API keys are provided via the secret name in the adapter config. All adapter actions are recorded in AegisClaw's audit log.

Security & Policies

- Use least-privilege scopes for skills (e.g., `files.read:/specific/path` rather than `files.read:/`).
- Require skill signing and verify signatures for production skills.
- Use the TUI approval flow for any skill that requests high-risk scopes.

Troubleshooting

- If a skill cannot reach the OpenClaw endpoint, check the egress proxy/egress rules and the adapter `endpoint` setting.
- Verify secrets are present: `./aegisclaw secrets list`
- Inspect audit logs for denied actions: `./aegisclaw logs`

## 🗺️ Roadmap

### Completed

- [x] **v0.1.x (Foundations)**: CLI, Policy Engine, TUI Approval, Hardened Docker, `age` Secrets, Audit Logging, OpenClaw Adapter, Egress Proxy, Signed Skills.
- [x] **v0.2.x (Policy & Runtimes)**: OPA (Rego) policy engine integration, gVisor (`sandbox_runtime`) support.
- [x] **v0.3.x (Observability & UX)**: Modern Web Dashboard, Real-time Terminal Streaming, Prometheus Metrics, OpenTelemetry Tracing, Active Secret Redaction, Emergency Lockdown (Panic Button).

### v0.4.x (Usability & Developer Experience)

- [x] **Package Manager Distribution**: Cross-platform install script, goreleaser with Windows builds.
- [x] **Interactive Init Wizard**: Guided first-run setup with environment detection (Docker, gVisor) and policy selection.
- [x] **Starter Skill Packs**: Pre-built skills (file-organiser, code-runner, git-stats) with Dockerfiles and manifests.
- [x] **`aegisclaw doctor`**: Single command to diagnose setup — Docker, secrets, audit integrity, policy engine, disk space.
- [x] **Docker-Compose Orchestration**: Multi-container skills with per-service scopes and isolated networks.
- [x] **Notification System**: Webhook and Slack alerts for pending approvals, denied actions, and emergencies.
- [x] **Policy Templates & Shell Completions**: Strict/standard/permissive Rego templates; bash/zsh/fish completions.

### v0.5.x (Advanced Security)

- [x] **Kata Containers / Firecracker**: MicroVM-based isolation with pluggable runtime interface.
- [x] **Pluggable Vault Backends**: HashiCorp Vault KV v2 with Store interface for future backends.
- [x] **LLM Guardrails**: Prompt injection detection, jailbreak prevention, secret leak sanitization.
- [x] **Runtime Behaviour Profiling**: Learn normal skill behaviour, flag anomalies (new network targets, memory/CPU spikes).
- [x] **Auth & Access Control**: RBAC roles (admin/operator/viewer), API token auth with constant-time comparison.

### v0.6.x (Ecosystem)

- [x] **Live Threat Map Dashboard**: WebSocket hub for real-time event streaming (audit, lockdown, posture).
- [x] **Agent X-Ray Mode**: Deep inspection of running skills (CPU, memory, network, processes via Docker API).
- [x] **Security Posture Score**: Gamified scoring of configuration quality with CLI badge (A–F grading).
- [x] **MCP Server**: Expose AegisClaw as an MCP tool for AI assistants (stdio transport).
- [x] **Skill Marketplace**: Local registry with ratings, security badges, search, and caching.
- [x] **VS Code Extension**: Sidebar panel for status, audit stream, skills, and Rego snippets.
- [x] **`aegisclaw simulate`**: Dry-run mode predicting skill behaviour without execution.

### v0.7.x (Multi-node & Monitoring)

- [x] **eBPF Runtime Monitoring**: Kernel-level event tracing (syscalls, files, network) for deep observability.
- [x] **Multi-Node Orchestration**: Distributed cluster with leader/follower roles, audit forwarding, and policy sync.

### Long-Term Vision

- [ ] **AegisClaw Cloud**: Multi-tenant SaaS with org/team hierarchy, managed registry, and hosted dashboards.
- [ ] **AI-Powered Policies**: LLM-assisted minimal-scope generation and behavior anomaly detection.

## 🤝 Contributing
We welcome contributions! Please see our [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to get started.

- [Bug Report](.github/ISSUE_TEMPLATE/bug_report.md)
- [Feature Request](.github/ISSUE_TEMPLATE/feature_request.md)

## 📜 License

Apache 2.0 - See [LICENSE](LICENSE) for details.

---

**Repository Topics:** `security`, `agent-runtime`, `sandbox`, `golang`, `ai-safety`, `docker`, `seccomp`
