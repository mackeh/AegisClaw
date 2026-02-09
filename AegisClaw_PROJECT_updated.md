# AegisClaw
**Secure-by-default runtime for OpenClaw-style personal AI agents**

> **Goal:** Make “agentic automation” safe enough for individuals by default, and scalable enough for teams—without losing the power of OpenClaw-style skills (email, calendar, terminal, browsers, chat apps, custom tools).

![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)
![CI](https://github.com/aegisclaw/aegisclaw/workflows/CI/badge.svg)

---

## What problem does AegisClaw solve?

Personal agents are great—right up until they can:
- read all your email and dump it into a chat,
- execute shell commands because a prompt said so,
- leak API keys stored in plaintext,
- install or run untrusted skills with no provenance,
- get prompt-injected through messages (“Ignore previous instructions…”) and do the wrong thing.

AegisClaw is the **runtime** and **security envelope** that makes these failures much harder to trigger—and much easier to detect, audit, and recover from.

---

## Design principles

1. **Secure by default**  
   No exposed ports, no plaintext secrets, no running as root, sensible network/file isolation out-of-the-box.

2. **Least privilege, capability-based access**  
   Every skill/tool request must declare what it needs (scopes). Users can approve once, deny, or require approval per action.

3. **Defense in depth**  
   Guardrails + policy engine + sandboxing + signed artifacts + auditability.

4. **Reproducible and auditable**  
   SBOMs, attestation, signed releases, deterministic builds (where possible).

5. **Human-in-the-loop where it matters**  
   Approvals for high-risk actions (payments, sending emails, running shell, file exfil, etc.).

---

## Core features

### Isolation & execution
- **Sandboxed tool execution**: Docker with hardened profiles; optional **gVisor**, **bubblewrap**, or **Firecracker**.
- **Non-root by default**: dropped Linux capabilities, seccomp, read-only filesystem, explicit writable mounts.
- **Network controls**: default-deny egress with allowlists (per-skill and per-action).

### Prompt & data safety
- **Prompt guardrails**: pluggable (NeMo Guardrails, OpenAI/Anthropic moderation hooks, custom regex/rules).
- **Sensitive-data redaction**: prevent secrets/PII from leaving the boundary unintentionally.
- **Context firewall**: blocks untrusted channels from overwriting system/tool policy.

### Secrets & configuration
- **Encrypted secrets**: SOPS + age (git-friendly).
- **Secret broker**: short-lived, scoped credentials injected at runtime (never stored in container layers/logs).

### Supply-chain security
- **Signed images & skills**: Cosign signatures verified on install.
- **Provenance & SBOM**: build attestation + SBOM generation (Syft/CycloneDX).
- **Vulnerability scanning**: Trivy/Grype integrated in CI and release gates.

### Governance, policy, audit
- **Policy engine**: OPA/Rego policies for tools/actions/scopes (local-first).
- **Audit log**: append-only, tamper-evident log of tool calls and approvals.
- **Observability**: OpenTelemetry traces/metrics + simple dashboard.

### Developer experience
- **CLI**: `aegisclaw` for setup, migration, skill management, policy editing, log review.
- **Skill SDK**: typed contracts, scope declarations, test harness, local mocking.

---

## Architecture (high-level)

```mermaid
graph TD
    U[User + Approval UI] --> P[Policy Engine (OPA)]
    M[Inbound Messages<br/>Email / Chat / Web] --> G[Guardrails + Context Firewall]
    G --> A[Agent Core<br/>(OpenClaw compatible)]
    A --> P
    P -->|allow/deny/require-approval| U
    A --> X[Sandbox Executor<br/>Docker + gVisor/bwrap/Firecracker]
    X --> T[Tools/Skills<br/>Email, Calendar, Shell, Browser...]
    S[Secrets (SOPS/age)] --> B[Secret Broker]
    B --> X
    L[Audit Log + Telemetry] --> D[Dashboard]
```

---

## Threat model (v1)

AegisClaw is built assuming:

### You are defending against
- **Prompt injection** via email/chat/web content
- **Malicious or compromised skills** (supply-chain attacks)
- **Secrets leakage** through logs, prompts, tool outputs, container layers
- **Over-permissioned tools** (agent can do more than intended)
- **Lateral movement** from sandbox to host

### You are not (yet) defending against
- **A fully compromised host OS**
- **Kernel-level exploits** without microVM isolation
- **Physical device compromise**
- **Advanced targeted attacks** without hardware-backed trust

---

## How it’s different from “just run it in Docker”

Docker is not a complete security boundary by itself. AegisClaw adds:
- policy + approvals + scopes,
- signed skills and provenance verification,
- secret brokerage and redaction,
- audit trails and tamper-evidence,
- optional microVM / user-space kernel isolation.

---

## Quickstart (local)

> **Status:** prototype-friendly; the commands below reflect the intended UX.

```bash
# 1) Install
curl -fsSL https://aegisclaw.dev/install.sh | sh

# 2) Initialize a local profile
aegisclaw init

# 3) Encrypt config
aegisclaw secrets init
aegisclaw secrets set OPENAI_API_KEY

# 4) Run with safe defaults
aegisclaw run
```

---

## Migration from OpenClaw

AegisClaw aims for **one-command migration**:
- imports skills,
- maps permissions to scopes,
- moves secrets into SOPS/age,
- disables risky defaults (open ports, broad FS mounts, root).

```bash
aegisclaw migrate openclaw --from ~/.openclaw
```

---

## Skills & permissions model

Every skill declares:
- required scopes (e.g., `email.read`, `email.send`, `shell.exec`, `files.read:/home/user/docs`)
- risk level hints (low/medium/high)
- safe defaults (rate limits, allowed recipients/domains, max attachment size)

Policy decides:
- allow / deny
- allow-with-approval
- allow-with-constraints (recipient allowlist, domain allowlist, time windows, etc.)

Example policy idea (conceptual):
- `shell.exec` always requires approval
- `email.send` requires approval unless recipient is in allowlist
- file reads only from a sandboxed “workspace” mount by default

---

## Roadmap

### v0.1 (MVP)
- CLI: init/run/logs/policy
- Docker sandbox with hardened defaults
- scope model + approval UI (TUI or local web UI)
- SOPS/age secrets
- audit log + basic telemetry
- OpenClaw-compatible skill wrapper layer

### v0.2
- OPA policy engine integration
- cosign signature verification for skills
- SBOM + provenance attestation
- safe browser tool (headless) in sandbox

### v0.3+
- gVisor/bwrap/Firecracker support
- enterprise modes (SSO, DLP hooks, centralized policy)
- multi-agent profiles and “workspaces”

---

## Project layout (suggested)

```
aegisclaw/
  cmd/                 # CLI entrypoints
  core/                # agent runtime + orchestration
  sandbox/             # execution backends (docker, gvisor, firecracker)
  policy/              # OPA + scopes + approvals
  secrets/             # SOPS/age + broker
  skills/              # skill SDK + examples
  observability/       # OTel + dashboard
  docs/
  tests/
```

---

## “Am I missing something?” — the big gaps to plan for

If you want this project to be *actually* hard to break, prioritize these early:

1. **A real permissions system (scopes) that cannot be bypassed**  
   Put policy checks in the runtime, not in prompts.

2. **A “context firewall”**  
   Treat inbound text as untrusted; prevent it from directly changing system instructions/tool rules.

3. **Exfiltration controls**  
   Redact secrets + restrict tool outputs + enforce egress allowlists (domain/IP).

4. **Skill provenance + sandbox boundary**  
   Signed skills, pinned digests, attestation, and a strict exec boundary.

5. **Tamper-evident audit trail**  
   If something goes wrong, you need forensic-quality records.

6. **Safe-by-default UX**  
   Users will accept defaults. Make the defaults conservative and explain approvals clearly.

---

## Alternative approaches (worth considering)

- **Capability-based “tool tokens”**  
  Instead of broad API keys, mint short-lived tokens per action (best for email/calendar APIs).
- **WASM sandbox for skills**  
  Run skills as WASM modules (Wasmtime) to reduce attack surface vs. containers.
- **Data diode approach**  
  Strict separation between “read-only” ingestion and “actuation” tools (two-stage approval).
- **Two-model setup**  
  Use a small “policy model” to classify risk + a main model to reason, with policy as the final gate.

---

## Contributing

- Issues: security bugs should go to **SECURITY.md** (private disclosure).
- Pull requests: include tests, policy changes, and documentation updates.

---

## Security

- **Security policy:** see `SECURITY.md`
- **Vuln reporting:** private disclosure preferred
- **Release signing:** all release artifacts should be signed and verifiable

---

## License

Apache 2.0 — see `LICENSE`.
