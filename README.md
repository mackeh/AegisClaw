# 🦅 AegisClaw

![CI](https://github.com/mackeh/AegisClaw/workflows/build/badge.svg)
![Go Version](https://img.shields.io/github/go-mod/go-version/mackeh/AegisClaw)
![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)

**Secure-by-default runtime for OpenClaw-style personal AI agents.**

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

- [x] **Phase 1: Foundation** - CLI skeleton & Config
- [x] **Phase 2: Policy Engine** - Scope definitions & Constraints
- [x] **Phase 3: Approval System** - TUI for user confirmation
- [x] **Phase 4: Sandbox** - Hardened Docker executor
- [x] **Phase 5: Secrets** - `age` encryption
- [x] **Phase 6: Audit** - Hash-chained logging
- [x] **Phase 7: Integration** - OpenClaw Protocol Adapter
- [x] **Phase 8: Network Control** - Egress filtering proxy
- [x] **Phase 9: Registry** - Signed skill distribution

## 🤝 Contributing

We welcome contributions! Please see our [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to get started.

- [Bug Report](.github/ISSUE_TEMPLATE/bug_report.md)
- [Feature Request](.github/ISSUE_TEMPLATE/feature_request.md)

## 📜 License

Apache 2.0 - See [LICENSE](LICENSE) for details.

---

**Repository Topics:** `security`, `agent-runtime`, `sandbox`, `golang`, `ai-safety`, `docker`, `seccomp`
