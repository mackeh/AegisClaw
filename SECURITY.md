# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

**Do not open public GitHub issues for security vulnerabilities.**

If you discover a security vulnerability in AegisClaw, please report it privately.

1.  **Email**: security@aegisclaw.dev (Replace with actual email)
2.  **Encryption**: Please use our [PGP Key](https://aegisclaw.dev/security.asc) (coming soon) to encrypt sensitive reports.
3.  **Response Timeline**: We aim to acknowledge reports within 24 hours and provide an initial assessment within 72 hours.

## Threat Model

AegisClaw is designed to protect against:

- **Malicious Skills**: Containment via Docker/gVisor and strict capability dropping.
- **Prompt Injection**: (Planned) Context firewall to sanitize inputs.
- **Over-permissioning**: Granular scope enforcement.

We currently **do not** protect against:

- Kernel-level exploits (without gVisor enabled).
- Physical access to the host machine.
- Compromised host OS user account (if `rootless` docker is not used).

## Security Audits

No third-party audits have been performed on v0.1 yet. Use at your own risk in production environments.
