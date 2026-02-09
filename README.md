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
- **✋ Human-in-the-Loop**: TUI-based approval system for high-risk actions.
- **🔐 Secret Encryption**: `age`-based encryption for sensitive API keys.
- **📜 Audit Logging**: Tamper-evident, hash-chained logs of all agent actions.

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

## 🗺️ Roadmap

### Completed

- [x] **v0.1.0-0.1.7 (Foundations)**: CLI, Policy Engine, TUI Approval, Hardened Docker, `age` Secrets, Audit Logging, OpenClaw Adapter.
- [x] **v0.1.8 (Egress Control)**: Integrated egress filtering proxy with audit trails.
- [x] **v0.1.9 (Signed Skills)**: Ed25519 signature verification and registry search/add.

### Upcoming (v0.2+)

- [ ] **Advanced Runtimes**: `docker-compose` support for easy multi-container setups. support for gVisor, Kata Containers, or Nix/bubblewrap for advanced users.
- [ ] **Safety Layer**: NeMo Guardrails integration for LLM prompt protection and custom execution rails.
- [ ] **Secret Brokering**: `sops` integration; pluggable support for HashiCorp Vault, Infisical, and Bitwarden.
- [ ] **Auth & Privacy**: Tailscale/WireGuard integration for private access; Authelia/Keycloak for web UI identity.
- [ ] **Observability**: OpenTelemetry instrumentation and simple dashboards (Prometheus/Grafana).
- [ ] **Skills Ecosystem**: Git-based skill distribution with enhanced hash-chained provenance.

## 🤝 Contributing

We welcome contributions! Please see our [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to get started.

- [Bug Report](.github/ISSUE_TEMPLATE/bug_report.md)
- [Feature Request](.github/ISSUE_TEMPLATE/feature_request.md)

## 📜 License

Apache 2.0 - See [LICENSE](LICENSE) for details.

---

**Repository Topics:** `security`, `agent-runtime`, `sandbox`, `golang`, `ai-safety`, `docker`, `seccomp`
