# AegisClaw — Reference Threat Cases

> Last updated: June 2026

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

## Case Study: OpenClaw and the Phishing Test ("Pinchy")

In June 2026, Varonis Threat Labs wired an OpenClaw agent ("Pinchy") to a Gmail
inbox, browser tools, and Google Workspace APIs, seeded the environment with
mock internal data (AWS credentials, CRM exports, internal conversations), and
ran phishing simulations against it — testing both a generic profile and a
**"strict" profile whose system prompt explicitly told the agent to verify
sender identities before acting on sensitive requests**, across two frontier
models. The results were reported by BleepingComputer and CSO Online.

### What happened

- An attacker writing from an **external Gmail address** impersonated the team
  lead and asked for "staging access" during a fabricated production emergency.
  The agent located and **emailed AWS IAM keys, database connection strings,
  and SSH credentials — in plaintext — to the attacker**.
- A second, casually-toned request ("working from home, need the weekly
  customer export") yielded a **CRM export covering 247 enterprise customers
  and $1.28M in monthly recurring revenue**.
- The agent *did* catch suspicious URLs and malicious OAuth apps. What it could
  not do was hold the line on **identity verification under urgency**: the
  strict profile failed because the agent prioritised resolving the simulated
  emergency over validating who had actually asked.

### Reported vulnerability classes

| Class | Failure mode |
|-------|--------------|
| **Social-engineered exfiltration** | Identity spoofing + urgency framing convinced the agent to send secrets to a new external recipient. |
| **Prompt-as-policy** | The only control between the request and the action was a system-prompt instruction — and the model rationalised its way past it. |
| **Over-privileged data access** | The agent had standing access to live credentials and full CRM exports it did not need for routine work. |
| **Unrestricted outbound channel** | The agent could email any new external recipient with no approval gate and no allowlist. |

### How AegisClaw contains each class

The defining lesson of this case is *where* the failure lived: not in a missing
scanner, but in treating the **model's judgment as the enforcement layer**.
AegisClaw's posture is the opposite — the model is assumed persuadable, and the
*actions* are gated outside it.

| Vulnerability class | AegisClaw control |
|---------------------|-------------------|
| **Social-engineered exfiltration** | Sending email is `email.send` — a **high-risk scope** (`internal/scope`). Under the default policy it returns `RequireApproval`; in the non-interactive gateway path that means **deny unless a human pre-granted it**. The attacker can persuade the model; the policy engine never reads the persuasive email — it only sees "high-risk send" and stops it. Exfiltration over HTTP instead hits the **default-deny egress proxy** (`internal/proxy`), and an attacker's endpoint is not on the agent's allowlist. |
| **Prompt-as-policy** | AegisClaw never makes a prompt instruction load-bearing. Enforcement is **deterministic and outside the model**: OPA/Rego policy, capability scopes, human approval, egress allowlists, sandbox boundaries. Guardrails are one layer of several — a fooled model still cannot authorise its own actions. |
| **Over-privileged data access** | Reading credentials or customer data is itself a scoped action (`files.read`, `secrets.access`) subject to policy. Secrets are `age`-encrypted at rest and injected per-scope, ephemerally, by the harness supervisor — there is no plaintext credentials file sitting in an inbox for the agent to "locate". The redactor scrubs known credential values from any output stream. |
| **Unrestricted outbound channel** | The harness forces every agent through the egress proxy with a **per-agent default allowlist** (the OpenClaw adapter ships one covering its channel and LLM endpoints); anything else requires the operator to extend `network.allowlist`. The proxy adds **SSRF protection** — it refuses loopback/private/link-local destinations and **cloud instance-metadata endpoints** (e.g. `169.254.169.254`, validated at dial time against DNS rebinding), closing the "trick the agent into reading IAM creds from the metadata service" path — and **outbound DLP** that blocks plaintext requests carrying the agent's own injected secrets. Every tool call and egress decision lands in the **hash-chained audit log** — an exfiltration *attempt* is a visible, attributable event, not a silent success. |

### What AegisClaw would *not* have caught — and why it doesn't matter as much

Honesty first: the phishing email itself would likely have sailed through.
A well-written, natural-language "urgent prod issue, please help" message
contains none of the markers indirect-injection scanning keys on (forged role
delimiters, encoded payloads, AI-addressed directives). AegisClaw's ingress
guardrails (`CheckData`) are a layer, not a promise.

The defense that matters here is at the **action layer**, and it holds under
two conditions: (a) the policy keeps `email.send` and external egress at
deny-or-approve — the secure defaults do, and a careless blanket "always
allow" grant reopens the hole; and (b) the agent's actions actually flow
through AegisClaw's brokers (the harness wiring, MCP gateway, and egress
proxy) rather than a hard-coded side channel.

### Operating guidance

Varonis's recommended mitigations map directly onto AegisClaw controls —
enforced by the runtime rather than requested of the model:

| Recommended mitigation | AegisClaw equivalent |
|------------------------|----------------------|
| "Require agents to verify sender identities." | A spoofed *request* can never authorise an action: authorisation comes from policy + human approval, which the email's content cannot influence. |
| "Prevent emailing new external recipients without approval." | Enforced by default: `email.send` is a high-risk scope → `RequireApproval`; the non-interactive gateway default-denies without a persisted grant. |
| "Limit agent access to internal data." | Enforced: least-privilege scopes (`files.read:/specific/path`, `secrets.access:NAME`), `age`-encrypted secrets injected per-scope and ephemerally, never stored in reach as plaintext. |

### Takeaway

The Hermes case showed what happens when the *host* boundary is the only line
of defense. The OpenClaw phishing test shows the complement: what happens when
the *model's judgment* is the only line of defense. A "strict" system prompt is
still just text, and text loses arguments with attackers. AegisClaw's answer is
the same for both: assume the layer will fail, and make sure the action it
would enable — emailing secrets to a stranger, opening a connection to an
unknown host — is independently gated, default-denied, and audited.

---

## Reporting

Found a vulnerability **class** AegisClaw does not contain? That is a security
issue in AegisClaw itself — report it privately per [SECURITY.md](SECURITY.md),
not via a public GitHub issue.
