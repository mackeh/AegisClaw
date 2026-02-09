# AegisClaw

**Secure-by-default runtime for OpenClaw-style personal AI agents**

> **Goal:** Make "agentic automation" safe enough for individuals by default, and scalable enough for teams—without losing the power of OpenClaw-style skills (email, calendar, terminal, browsers, chat apps, custom tools).

![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)
![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go&logoColor=white)

---

## What problem does AegisClaw solve?

Personal agents are great—right up until they can:

- read all your email and dump it into a chat,
- execute shell commands because a prompt said so,
- leak API keys stored in plaintext,
- install or run untrusted skills with no provenance,
- get prompt-injected through messages and do the wrong thing.

AegisClaw is the **runtime** and **security envelope** that makes these failures much harder to trigger—and much easier to detect, audit, and recover from.

---

## Features

- 🔒 **Capability-based permissions** - Skills must declare scopes (`email.send`, `shell.exec`, etc.)
- 👤 **Human-in-the-loop approvals** - High-risk actions require explicit approval
- 🐳 **Sandboxed execution** - Docker with hardened seccomp profiles, no root
- 🔐 **Encrypted secrets** - SOPS/age encrypted, never stored plaintext
- 📜 **Tamper-evident audit log** - Hash-chained entries for forensic analysis
- 🛡️ **Default-deny networking** - Explicit allowlists per skill

---

## Quickstart

```bash
# Build from source
go build -o aegisclaw ./cmd/aegisclaw

# Initialize configuration
./aegisclaw init

# View default policy
./aegisclaw policy list

# Start the runtime
./aegisclaw run
```

---

## Project Structure

```
AegisClaw/
├── cmd/aegisclaw/       # CLI entrypoint
├── internal/
│   ├── config/          # Configuration loading
│   ├── scope/           # Permission model
│   ├── policy/          # Policy engine
│   ├── audit/           # Tamper-evident logging
│   ├── approval/        # TUI approval system (coming soon)
│   ├── sandbox/         # Docker executor (coming soon)
│   └── secrets/         # SOPS/age manager (coming soon)
├── configs/             # Seccomp profiles
└── docs/
```

---

## Roadmap

- [x] **v0.1-alpha** - CLI skeleton, scope model, policy engine, audit logging
- [ ] **v0.1** - TUI approvals, Docker sandbox, SOPS secrets
- [ ] **v0.2** - OPA integration, Cosign skill verification
- [ ] **v0.3** - gVisor/Firecracker, enterprise features

---

## License

Apache 2.0 — see [LICENSE](LICENSE)
