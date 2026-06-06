# AegisClaw — Harness Architecture (v2 Design)

> Status: **Proposal** · Author: design pass, June 2026 · Supersedes the implicit
> "skill executor" model for the agent-harness use case.

## 1. Motivation: AegisClaw governs the wrong thing

AegisClaw's enforcement stack — policy, guardrails, redaction, audit, eBPF,
sandbox — currently hangs off a single entry point: `agent.ExecuteSkill()`,
which launches a Docker container that **AegisClaw itself** starts. Everything
flows through that one path.

But the agents AegisClaw exists to protect do not work that way:

- **Hermes** (Nous Research) is an autonomous *execution loop* with 40+ built-in
  tools — terminal, code execution, browser automation, file ops — and it
  **auto-generates its own skill files** at runtime.
- **OpenClaw** is a **WebSocket gateway** fanning 50+ messaging channels
  (Telegram, Discord, Signal, …) into an agent runtime with a plugin ecosystem.

Neither agent asks AegisClaw's permission before acting. They run as independent
processes: they make their own LLM calls, invoke their own tools, write their own
files, and open their own sockets. **AegisClaw sees none of it.**

The `internal/openclaw` "adapter" that the README describes as mediating
"communication between agents and external services" is, in the actual code
(`internal/openclaw/health.go`), a single HTTP **health-check ping**. There is no
mediation, no interception, no enforcement.

**Consequence:** today's controls only protect the narrow case where a human
manually runs `aegisclaw sandbox run-skill`. The agents we actually want to
harness run completely unsupervised beside the runtime.

This document proposes the architectural change that closes that gap.

## 2. Goals & non-goals

**Goals**

1. Place AegisClaw's enforcement **inline on the real action paths** of a running
   agent, not on a parallel skill executor.
2. Support **OpenClaw and Hermes as first-class adapters**, and **any other
   agent** through a generic adapter — "not only limited to those."
3. Reuse the existing enforcement primitives (policy, guardrails, redactor,
   audit, sandbox, secrets, scope, approval) as a shared core that every plane
   calls into. **We are relocating enforcement, not rewriting it.**
4. Make the unshipped roadmap items (tool-poisoning defense, agentic-loop/cost
   guards) emergent properties of the new planes rather than bolt-ons.

**Non-goals (for this design)**

- Multi-node clustering (`internal/cluster` is a half-finished gRPC stub;
  parked behind a build tag — out of scope for a personal/test harness).
- Replacing OPA/Rego, the audit hash chain, or the sandbox hardening. These are
  the crown jewels and stay.
- Becoming an agent framework. AegisClaw remains a *security envelope*; it never
  implements agent reasoning.

## 3. The pivot: from "skill executor" to "agent control plane"

The 2026 consensus across Microsoft's Agent Governance Toolkit, NVIDIA's agent
sandboxing guidance, and the MCP-gateway vendors converges on one idea:

> A harness is a **deterministic runtime layer that wraps the agent** and sits
> inline on every action the model proposes — validating, authorizing,
> executing, and logging it.

For an autonomous agent there are exactly **four action paths** worth
intercepting. AegisClaw should own all four as **inline brokers**:

| Plane | What the agent does | Interception point | Existing asset |
|---|---|---|---|
| **Tools** | Calls MCP / built-in tools | **MCP gateway** the agent is pointed at | `internal/mcp` (server → must become a *proxy*) |
| **Model** | Calls an LLM provider | **LLM proxy** (OpenAI/Anthropic-compatible) | `guardrails`, `redactor` (need an HTTP shim) |
| **Network** | Arbitrary HTTP / egress | **Egress proxy** (already built) | `internal/proxy` (make mandatory + inspecting) |
| **Host** | Files / processes / syscalls | **Sandbox the agent runs *inside*** | `internal/sandbox`, `internal/ebpf` |

The key realization: **AegisClaw already owns ~80% of the enforcement
primitives.** What is missing is the *inline plumbing* that forces a real agent's
traffic through them.

```
          ┌──────────────────────── AegisClaw Harness ────────────────────────┐
          │                                                                    │
          │   ┌────────────┐   tool calls   ┌──────────────┐                   │
 agent ───┼──▶│ MCP Gateway │──────────────▶│ real MCP srvs │                  │
 (Hermes/ │   └─────┬──────┘                 └──────────────┘                  │
 OpenClaw/│         │ policy · approval · audit · tool-desc pinning            │
 generic) │   ┌─────▼──────┐  model calls   ┌──────────────┐                   │
   runs   ├──▶│ LLM Proxy   │──────────────▶│ LLM provider │                   │
  INSIDE  │   └─────┬──────┘  guardrails · redact · budgets └──────────────┐   │
   the    │   ┌─────▼──────┐   egress       ┌──────────────┐               │   │
 sandbox  ├──▶│ Egress Proxy│──────────────▶│ the internet │  DLP · SSRF · │   │
          │   └─────┬──────┘   allowlist     └──────────────┘  inj. scan    │   │
          │         │                                                       │   │
          │   ┌─────▼───────────────────────────────────────────────┐      │   │
          │   │  Shared core: OPA policy · guardrails · redactor ·   │◀─────┘   │
          │   │  audit (hash chain) · scope · approval · secrets     │          │
          │   └──────────────────────────────────────────────────────┘         │
          │   sandbox (gVisor/Firecracker) + eBPF wrap the agent process        │
          └────────────────────────────────────────────────────────────────────┘
```

## 4. The pluggable agent-adapter model

Today there is no agent abstraction — OpenClaw is hardcoded as a health check.
We introduce a real interface so OpenClaw and Hermes are simply the first two
implementations, and a generic adapter covers everything else.

```go
// internal/harness/adapter.go

// AgentAdapter teaches the harness how to launch a specific agent inside the
// security envelope and how to police that agent's specific risk surface.
type AgentAdapter interface {
    Name() string // "generic", "openclaw", "hermes"

    // Launch starts the agent process inside the harness. The adapter does NOT
    // get a raw process; it receives a HarnessEnv whose wiring already points
    // the agent at AegisClaw's brokers.
    Launch(ctx context.Context, env HarnessEnv) (AgentProcess, error)

    // Wiring declares how the agent must be configured so its four action
    // paths are brokered. The supervisor injects these before Launch.
    Wiring() Wiring

    // IngressSources are agent-specific untrusted-input channels that must be
    // scanned with guardrails.CheckData before reaching the model.
    //   OpenClaw -> chat-channel messages (Telegram/Discord/…)
    //   Hermes   -> self-generated skill files + tool outputs
    IngressSources() []IngressSource

    Health(ctx context.Context) Health // folds in today's openclaw health check
}

// Wiring is the set of environment/config overrides that force the agent's
// traffic through AegisClaw's inline brokers.
type Wiring struct {
    LLMBaseURL   string            // -> AegisClaw LLM proxy (OPENAI_BASE_URL, …)
    MCPEndpoint  string            // -> AegisClaw MCP gateway
    HTTPProxy    string            // -> AegisClaw egress proxy (HTTP(S)_PROXY)
    Env          map[string]string // adapter-specific extras
    Secrets      []ScopedSecret    // scoped, ephemeral, injected at launch
}
```

A `Registry` maps adapter names to implementations; `aegisclaw harness run
--agent hermes ...` selects one. Unknown agents default to `generic`.

### 4.1 What each adapter polices

- **Generic adapter** — any agent that honours `HTTP(S)_PROXY` + an
  OpenAI-compatible base URL + an MCP endpoint gets the full envelope with **zero
  bespoke code**. This is what makes the harness "not only limited to those two."
- **OpenClaw adapter** — risk surface is the **inbound channel messages**.
  Untrusted text from 50+ chat platforms is a textbook indirect-prompt-injection
  vector, so the adapter routes inbound messages through `guardrails.CheckData`
  *before* they reach the model and gates plugin/tool calls at the MCP gateway.
  The existing HTTP health check becomes its `Health()`.
- **Hermes adapter** — risk surface is the **self-improvement loop**. Hermes
  writes and executes its own code and auto-generates skills, so the adapter
  (a) runs the whole Hermes process inside gVisor/Firecracker, (b) intercepts
  terminal/code-exec/browser tools at the MCP gateway, (c) **hash-pins and
  re-approves every newly self-generated skill** (the unshipped tool-poisoning
  defense), and (d) enforces loop/cost budgets on the execution loop.

This mirrors the agents' real architectures (Hermes = loop+tools; OpenClaw =
gateway+channels) instead of pretending both are "a container we launch."

## 5. Priority plane: the MCP gateway — ✅ shipped

This is the single highest-leverage change and the first to build. It is also
where the entire industry is converging (Kong AI MCP Proxy, Azure APIM, Operant,
MintMCP): the MCP gateway is the dominant interception point for agent tool
calls in 2026.

### 5.1 From server to proxy

`internal/mcp` today is an MCP **server** that exposes AegisClaw's *own* tools
(`aegisclaw_list_skills`, etc.) over stdio. We flip it into an MCP **gateway**:
the agent points its MCP client at AegisClaw; AegisClaw forwards (some of) those
calls to the *real* downstream MCP servers, applying enforcement on every call.

```
agent's MCP client ──▶ AegisClaw MCP gateway ──▶ downstream MCP server(s)
                          │
                          ├─ tool discovery: merge + hash-pin descriptions
                          ├─ per-call: scope mapping → OPA policy decision
                          ├─ RequireApproval → TUI / dashboard / Slack card
                          ├─ argument DLP (redactor) + indirect-injection scan
                          ├─ rate limit (already exists: ratelimit.go)
                          └─ append to hash-chained audit (already exists)
```

### 5.2 Per-call enforcement pipeline

For each `tools/call`:

1. **Identify** the tool + downstream server; map to a `scope.Scope`
   (e.g. `fs.write:/etc` → `files.write` at risk High).
2. **Policy**: `policy.EvaluateRequest()` → `Allow` / `Deny` / `RequireApproval`.
   Reuses the existing OPA engine and the three Rego templates verbatim.
3. **Approval**: on `RequireApproval`, raise an approval card (TUI today; the
   dashboard/Slack path already exists for skills) and honour persistent grants.
4. **Argument inspection**: run tool-call arguments through `redactor` (block
   credential exfiltration) and `guardrails.CheckData` (catch injection smuggled
   into arguments).
5. **Forward** to the downstream server only if allowed.
6. **Response inspection**: scan the tool result with `guardrails.CheckData`
   before it returns to the agent — poisoned tool output cannot silently
   re-enter the model's context.
7. **Audit**: one hash-chained entry per call (method, tool, decision, latency,
   redacted args), extending the existing `audit/mcp.log`.

### 5.3 Tool-description pinning (tool-poisoning defense)

On first discovery, hash each tool's name + description + input schema and store
the pin. On every subsequent discovery, re-hash and compare; a changed
description **forces re-approval** before the tool is usable. This is the
"tool-poisoning / rug-pull" defense listed as unshipped in the roadmap — it falls
out of the gateway naturally.

### 5.4 Reused vs. new

- **Reused:** `policy`, `scope`, `approval`, `audit`, `guardrails`, `redactor`,
  `ratelimit`. These are called, not rewritten.
- **New:** an MCP client to talk to downstream servers; the forwarding loop;
  description pinning store; a config block listing downstream servers + their
  scope mappings.

## 6. The other three planes (subsequent phases)

- **Sandbox-the-agent** (`internal/sandbox`, `internal/ebpf`): run the agent
  process itself inside gVisor/Firecracker with read-only rootfs, dropped caps,
  scoped writable mounts, and eBPF syscall/file/network tracing. ✅ *Shipped via
  `sandboxlauncher` + `DockerExecutor.Start`* (Phase 1). Remaining follow-ups:
  scoped writable mounts and attaching eBPF tracing to the agent container.
- **LLM proxy** (`internal/llmproxy`, new, small): an OpenAI/Anthropic-compatible
  reverse proxy that runs `guardrails.CheckInput`/`CheckOutput` + `redactor`
  inline and enforces **token/cost + loop budgets** (per tool call, per task
  loop, per session — the three-level timeout model). Closes the unshipped
  "agentic loop & cost guards" item; the detection logic already exists.
- **Egress proxy** (`internal/proxy`): exists but is optional/per-skill. Make it
  the **mandatory, content-inspecting** egress broker for the agent: DLP on
  requests (credential leak), injection scan on responses, SSRF blocking,
  default-deny allowlist.

## 7. Mapping to the existing codebase

**Keep & promote (shared enforcement core):** `policy`, `guardrails`,
`redactor`, `audit`, `sandbox`, `secrets`, `scope`, `approval`, `posture`, and
the `server` dashboard. Every plane calls into these.

**Refactor into inline brokers:**
- `internal/mcp` — server → **gateway/proxy** (Section 5).
- `internal/proxy` — optional → **mandatory, inspecting** egress broker.
- **new** `internal/llmproxy` — inline model broker.

**New glue:**
- `internal/harness` — the `AgentAdapter` interface, the `Registry`, and the
  **supervisor** that launches an agent with all four planes wired.
- `internal/harness/adapters/{generic,openclaw,hermes}` — the three adapters
  (`generic` shipped; OpenClaw/Hermes pending).
- `internal/harness/sandboxlauncher` — the sandbox-backed `Launcher` (keeps the
  Docker dependency out of the core harness package).

**Reconsider / de-emphasize:**
- `internal/cluster` — half-finished gRPC stub (TODO at `cluster.go:131`, no
  service handlers). Park behind a build tag; multi-node is premature for a
  personal/test harness.
- `internal/agent.ExecuteSkill` — stays for the existing manual skill-run flow,
  but is no longer the *only* enforcement path; the harness supervisor becomes
  the primary entry point.

**New CLI surface (illustrative):**
```
aegisclaw harness run --agent hermes -- hermes serve   # launch agent in envelope
aegisclaw harness run --agent openclaw -- openclaw up
aegisclaw harness run --agent generic --cmd "./my-agent"
aegisclaw gateway mcp --upstream <server-url>          # standalone MCP gateway
aegisclaw harness status                               # 4 planes per agent
```

## 8. Phasing

1. **`internal/harness` + adapter interface + generic adapter.** ✅ *Done.*
   Launch any agent with the egress proxy + scoped ephemeral secrets forced on,
   the whole lifecycle recorded to the hash-chained audit log. Shipped as
   `internal/harness` (`AgentAdapter`, `Registry`, `Supervisor`, `Launcher`) with
   a `generic` adapter and an `aegisclaw harness run` CLI. Two launchers
   implement the `Launcher` interface:
   - `ProcessLauncher` (default) runs the agent as a **host subprocess** pointed
     at the egress proxy via `HTTP(S)_PROXY`, so even a host process is filtered.
   - `sandboxlauncher.Launcher` (`--image`) runs the agent **inside a hardened
     sandbox container** (read-only rootfs, all caps dropped, `no-new-privileges`,
     resource limits; `--runtime gvisor` for stronger isolation). The egress
     proxy address is rewritten to `host.docker.internal` and the host
     environment is not inherited. This completes the "agent runs inside the
     sandbox" goal and reuses the existing `internal/sandbox` hardening via a new
     detached `DockerExecutor.Start` entry point.
2. **MCP gateway** (Section 5). ✅ *Done.* Per-call policy/approval/audit +
   description pinning. Shipped as `mcp.Gateway` (an inline proxy over a
   `Downstream`; `StdioDownstream` spawns a real MCP server over stdio) with
   `mcp.PinStore` for tool-description hash-pinning and the `aegisclaw gateway
   mcp` / `gateway pins` CLI. Reuses `policy`, `guardrails`, `audit`, `scope`,
   and the existing rate limiter; runs non-interactively, so RequireApproval
   resolves against persisted "always" grants and otherwise default-denies.
   Closes two unshipped roadmap items (tool-poisoning defense; untrusted
   tool-call surface).
3. **LLM proxy.** Inline guardrails + redaction + token/cost/loop budgets. Closes
   the loop-guard item.
4. **First-class OpenClaw & Hermes adapters** policing each one's specific risk
   surface (channels vs. self-generated skills).
5. **Dashboard + posture** updated to show the four live planes per agent instead
   of a single health ping.

## 9. Open questions

- **MCP transport:** downstream servers may be stdio or HTTP/SSE. The gateway
  should support both; stdio downstreams are spawned as child processes (and can
  themselves be sandboxed).
- **Agent cooperation:** the generic adapter assumes the agent honours
  `HTTP(S)_PROXY` and a configurable LLM base URL / MCP endpoint. Agents that
  hard-code endpoints need either the sandbox-level egress proxy (transparent
  interception) or a small adapter shim.
- **Approval fatigue:** per-tool-call approval can be noisy. Persistent grants +
  policy-driven auto-allow for low-risk scopes (both already exist) mitigate
  this; tuning the default Rego templates for the gateway is follow-up work.
- **Hermes self-generated skills:** need a concrete hook for "a new skill file
  appeared" — likely a filesystem watch on the sandbox's skill output mount,
  feeding the description-pinning + approval flow.

## 10. Reference points

Landscape and standards this design draws on (2026):

- MCP gateways / proxies as the agent tool-call control point — Kong AI MCP
  Proxy, Azure API Management, Operant, MintMCP, Gravitee.
- Microsoft Agent Governance Toolkit + NVIDIA sandboxing guidance: the four
  mandatory layers (network egress, filesystem boundaries, secrets scoping,
  config protection).
- "Design Patterns for Securing LLM Agents against Prompt Injections"
  (arXiv:2506.08837).
- Isolation tiers: Firecracker microVMs / gVisor / V8 isolates.
- Three-level timeouts: per tool call, per task loop, per sandbox lifetime.
