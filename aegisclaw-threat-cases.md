# AegisClaw — Reference Threat Cases

> Last updated: May 2026

AegisClaw exists to wrap autonomous AI agents in a security envelope. The
clearest argument for that envelope is what happens to agents that run without
one. This document tracks real-world agent security incidents and maps each
vulnerability **class** to the concrete AegisClaw control that contains it.

These are reference cases compiled from publicly reported disclosures. CVE
identifiers are cited as published; AegisClaw makes no independent claim about
the current state of any third-party project. The value here is the
**vulnerability classes** — they recur across autonomous agents, and AegisClaw
is designed to neutralise every one of them.

---

## Case Study: The Hermes Agent

The Hermes agent (NousResearch) is an autonomous, *self-improving* agent that
can write and execute its own code. That capability is powerful and, run in an
unprotected environment, dangerous: a series of publicly reported
vulnerabilities showed how an autonomous agent with code-execution rights can
escalate into full OS compromise.

### Reported vulnerability classes

| Class | Reported failure mode |
|-------|----------------------|
| **Unauthenticated RCE** | The API server and webhook integrations could run with authentication disabled by default, letting remote network clients execute arbitrary OS commands. |
| **Sandbox / filter bypass** | The `skills_guard` scanner was bypassed entirely using dynamic string construction, defeating keyword-based safety checks. |
| **Symlink traversal** (CVE-2026-7397) | Local attackers used symlink manipulation to bypass path checks and write into protected system directories. |
| **Credential exposure** (CVE-2026-22798) | With `HERMES_REDACT_SECRETS` off by default, the agent emitted live API keys into visible chat responses and unencrypted logs. |

The unifying lesson: an autonomous agent must be assumed hostile to its own
host. Authentication, path checks, and keyword scanners are all *single* layers
— and single layers get bypassed.

### How AegisClaw contains each class

AegisClaw's posture is **default-deny and defense-in-depth**: no single
control is load-bearing.

| Vulnerability class | AegisClaw control |
|---------------------|-------------------|
| **Unauthenticated RCE** | `aegisclaw serve` binds to loopback by default and **refuses an unauthenticated non-loopback bind** (`internal/server/bind.go`). Every API endpoint sits behind RBAC middleware (`admin`/`operator`/`viewer`) with constant-time API-token comparison (`internal/server/auth.go`). Skills never execute on the host — only inside the hardened sandbox. Network egress is default-deny. |
| **Sandbox / filter bypass** | Guardrails are *not* the only barrier. Even if a guard is evaded, the skill still runs in a Docker/gVisor sandbox with **all capabilities dropped, read-only rootfs, `no-new-privileges`, non-root user, and PID/memory/CPU limits**. Separately, **Guardrails 2.0** normalises text before matching — defeating exactly the "dynamic string construction" / obfuscation evasion that bypassed `skills_guard` (homoglyphs, zero-width characters, encoding, letter-spacing). |
| **Symlink traversal** | Skill manifest file access is confined with `OpenRoot` (v0.7.1 hardening) and rejects `..` traversal. The sandbox rootfs is **read-only** and the container has no bind mount to host system directories, so a symlink inside the container resolves to nothing privileged. |
| **Credential exposure** | **Active secret redaction is on by default** — the redactor wraps every skill output stream (`internal/security/redactor/`), so leaked secrets are scrubbed before they reach a log or console. Secrets are stored `age`-encrypted and injected as scoped environment variables, never written to disk in plaintext. |

### Operating guidance

The mitigations recommended for running Hermes safely map directly onto
AegisClaw defaults — AegisClaw is, in effect, that mitigation set enforced by
the runtime rather than left to the operator:

| Recommended mitigation | AegisClaw equivalent |
|------------------------|----------------------|
| "Never use local execution by default — run inside an isolated container/VM." | AegisClaw runs **every** skill in a sandbox. There is no unsandboxed execution path. |
| "Do not bind the API server to `0.0.0.0` without strong API keys." | Enforced: `aegisclaw serve` binds to loopback by default and **refuses an unauthenticated non-loopback bind**. Exposing it on the network requires API tokens in `~/.aegisclaw/auth.yaml`; every endpoint is then behind RBAC. |
| "Set strict guards — scan all autonomously created skills." | Set `guardrails.mode: block`; require signed (Ed25519) skill manifests; keep policy mode at `strict`/`standard`. |
| "Turn on secret redaction." | Redaction is **on by default** and cannot be silently disabled. |

### Takeaway

Hermes' incidents were not exotic — they were the *standard* failure modes of
an autonomous agent: an exposed control plane, a bypassable scanner, a path
check, and an opt-in redaction flag. AegisClaw's design assumes each of those
will fail and layers a sandbox, default-deny networking, encrypted secrets, and
tamper-evident audit underneath, so that a single bypass is contained rather
than catastrophic.

---

## Reporting

Found a vulnerability **class** AegisClaw does not contain? That is a security
issue in AegisClaw itself — report it privately per [SECURITY.md](SECURITY.md),
not via a public GitHub issue.
