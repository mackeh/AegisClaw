// Package harness is the agent control plane: it launches an AI agent inside
// AegisClaw's security envelope and brokers the four action paths an autonomous
// agent uses — tools, model, network, and host.
//
// Phase 1 (this package) establishes the adapter/supervisor seam and wires the
// network plane (a forced egress proxy) and scoped, ephemeral secret injection.
// The tools plane (MCP gateway), model plane (LLM proxy), and a sandbox-backed
// launcher land in later phases; the types here are shaped to accept them
// without an interface break.
package harness

import (
	"context"
	"io"
)

// Plane identifies one of the four agent action paths the harness brokers.
type Plane string

const (
	PlaneTools   Plane = "tools"   // MCP / built-in tool calls (Phase 2)
	PlaneModel   Plane = "model"   // LLM provider calls (Phase 3)
	PlaneNetwork Plane = "network" // arbitrary HTTP egress (Phase 1)
	PlaneHost    Plane = "host"    // files / processes / syscalls (sandbox)
)

// ScopedSecret names a stored secret the agent needs and the capability scope
// that gates it. The value is resolved lazily by the supervisor from the
// encrypted secret store and is never written to the manifest, the audit log,
// or anywhere on disk — only injected into the agent's environment for the
// lifetime of the process.
type ScopedSecret struct {
	EnvVar     string // environment variable the value is injected as
	SecretName string // key in the AegisClaw secret store
	Scope      string // capability gated on, e.g. "secrets.access:OPENAI_API_KEY"
}

// IngressSource is an untrusted-input channel an adapter exposes — for OpenClaw,
// a chat channel (Telegram/Discord/…); for Hermes, the directory it writes
// self-generated skills into. Phase 1 records them in the audit log so the
// surface is visible; later phases route them through guardrails.CheckData
// before the content can reach the model.
type IngressSource struct {
	Name string // "telegram", "discord", "skill-file-watch", …
	Kind string // "chat-channel", "filesystem", "tool-output"
}

// Wiring is the set of broker endpoints and environment the supervisor injects
// so the agent's action paths route through AegisClaw. The supervisor fills in
// the broker URLs; an adapter supplies only agent-specific defaults.
type Wiring struct {
	HTTPProxy   string            // egress proxy URL (set by supervisor, Phase 1)
	LLMBaseURL  string            // LLM proxy base URL (Phase 3; empty in Phase 1)
	MCPEndpoint string            // MCP gateway endpoint (Phase 2; empty in Phase 1)
	Env         map[string]string // adapter-specific extra environment
	Secrets     []ScopedSecret    // scoped, ephemeral secrets to inject
}

// HarnessEnv is the fully-resolved launch environment handed to a Launcher.
type HarnessEnv struct {
	Wiring          Wiring
	Command         []string          // agent process argv
	WorkDir         string            // working directory ("" inherits cwd)
	Image           string            // container image (sandbox launcher only)
	ResolvedSecrets map[string]string // EnvVar -> value (policy-permitted only)
	Stdout          io.Writer
	Stderr          io.Writer
}

// AgentProcess is a running agent under the harness.
type AgentProcess interface {
	// Wait blocks until the agent exits and returns its exit code. A non-zero
	// exit code is not an error; err is non-nil only for unexpected failures.
	Wait() (int, error)
	// Stop requests termination of the agent process.
	Stop() error
}

// Health reports adapter readiness, mirroring the existing adapter health model.
type Health struct {
	Status  string `json:"status"`
	Ready   bool   `json:"ready"`
	Message string `json:"message"`
}

// AgentAdapter teaches the harness how to run and police a specific agent.
// Implementations are deliberately thin: the supervisor owns launching (via a
// Launcher) so the host-subprocess and future sandbox-backed paths stay uniform
// across every adapter. OpenClaw and Hermes are the first two implementations;
// the generic adapter covers any agent that honours standard proxy/endpoint
// environment variables.
type AgentAdapter interface {
	// Name is the adapter's stable identifier, e.g. "generic".
	Name() string

	// DefaultWiring returns the agent-specific wiring template. The supervisor
	// overrides HTTPProxy (and, in later phases, LLMBaseURL/MCPEndpoint).
	DefaultWiring() Wiring

	// IngressSources lists untrusted-input channels to be guarded.
	IngressSources() []IngressSource

	// PrepareCommand translates the user's argv into the actual process argv
	// (e.g. an adapter may prefix its agent binary or a subcommand). The
	// generic adapter returns it unchanged. Returning an error aborts launch.
	PrepareCommand(userArgs []string) ([]string, error)

	// Health reports whether the adapter and its agent are ready.
	Health(ctx context.Context) Health
}
