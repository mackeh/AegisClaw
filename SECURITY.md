# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.10.x  | :white_check_mark: |
| 0.9.x   | :white_check_mark: |
| < 0.9   | :x:                |

## Reporting a Vulnerability

**Do not open public GitHub issues for security vulnerabilities.**

If you discover a security vulnerability in AegisClaw, please report it privately.

1.  **Email**: security@aegisclaw.dev
2.  **Response Timeline**: We aim to acknowledge reports within 24 hours and provide an initial assessment within 72 hours.

## Threat Model

AegisClaw is designed to protect against:

- **Malicious Skills**: Containment via Docker/gVisor and strict capability dropping.
- **Secrets Leakage**: **Active Secret Redaction** automatically scrubs secrets from logs and console output.
- **Runaway Agents**: **Emergency Lockdown** ("Panic Button") instantly kills all containers and blocks execution.
- **Over-permissioning**: Granular OPA-based scope enforcement.
- **Prompt Injection (Direct & Indirect)**: Evasion-resistant LLM guardrails detect injection and jailbreak attempts in user prompts, model responses, and untrusted data the agent ingests — including payloads obfuscated with homoglyphs, zero-width characters, or encoding.
- **Unauthenticated API Exposure**: `aegisclaw serve` binds to loopback by default and refuses a non-loopback bind without API-token authentication; RBAC (admin/operator/viewer) guards every API endpoint.

We currently **do not** protect against:

- Physical access to the host machine.
- Compromised host OS user account (if `rootless` docker is not used).

## Reference Threat Cases

AegisClaw's controls are validated against the standard failure modes of
autonomous agents — unauthenticated RCE, sandbox/filter bypass, path/symlink
traversal, and credential exposure. [`aegisclaw-threat-cases.md`](aegisclaw-threat-cases.md)
documents real-world agent incidents (e.g. the Hermes agent) and maps each
vulnerability **class** to the specific AegisClaw control that contains it.

The guiding principle is **defense-in-depth**: no single control — not the
guardrails, not authentication, not a path check — is load-bearing. A bypass of
any one layer is contained by the sandbox, default-deny networking, encrypted
secrets, and tamper-evident audit beneath it.

## Security Audits

No third-party audits have been performed yet. Use at your own risk in production environments.
