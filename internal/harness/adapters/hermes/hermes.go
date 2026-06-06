// Package hermes provides a first-class AgentAdapter for the Hermes agent.
//
// Hermes is an autonomous, self-improving agent: it runs a "do, learn, improve"
// loop, has 40+ built-in tools including terminal access and code execution, and
// auto-generates reusable skill files at runtime. Its defining risk surface is
// therefore self-modifying code and self-generated skills, so this adapter
// requires the sandbox (RequiresSandbox), declares the self-generated skills
// directory as a filesystem ingress source to be scanned, and ships a default
// egress allowlist for the LLM and skill-distribution endpoints it uses.
package hermes

import (
	"context"
	"os/exec"

	"github.com/mackeh/AegisClaw/internal/harness"
)

const binary = "hermes"

// Adapter is the Hermes agent adapter.
type Adapter struct{}

// New returns a Hermes adapter.
func New() *Adapter { return &Adapter{} }

// Name returns the adapter identifier.
func (a *Adapter) Name() string { return "hermes" }

// DefaultWiring declares Hermes's scoped secrets (LLM provider keys), injected
// from the encrypted store if present.
func (a *Adapter) DefaultWiring() harness.Wiring {
	return harness.Wiring{
		Env: map[string]string{},
		Secrets: []harness.ScopedSecret{
			{EnvVar: "OPENAI_API_KEY", SecretName: "OPENAI_API_KEY", Scope: "secrets.access:OPENAI_API_KEY"},
			{EnvVar: "ANTHROPIC_API_KEY", SecretName: "ANTHROPIC_API_KEY", Scope: "secrets.access:ANTHROPIC_API_KEY"},
		},
	}
}

// IngressSources reports the directory Hermes writes self-generated skills into
// (and its tool outputs) — untrusted content the agent produces and re-ingests,
// which must be scanned before it can steer the agent.
func (a *Adapter) IngressSources() []harness.IngressSource {
	return []harness.IngressSource{
		{Name: "self-generated-skills", Kind: "filesystem"},
		{Name: "tool-output", Kind: "tool-output"},
	}
}

// DefaultEgressDomains is a baseline allowlist for Hermes's LLM and skill
// endpoints. Hermes's broad tool use (browser automation, code execution) will
// typically need more — operators extend it via network.allowlist.
func (a *Adapter) DefaultEgressDomains() []string {
	return []string{
		"api.openai.com",
		"api.anthropic.com",
		"openrouter.ai",
		"github.com",
		"raw.githubusercontent.com",
	}
}

// RequiresSandbox reports true: Hermes executes its own code, so running it
// outside the sandbox is unsafe.
func (a *Adapter) RequiresSandbox() bool { return true }

// PrepareCommand defaults the binary to "hermes" when the user passes only a
// subcommand (or nothing).
func (a *Adapter) PrepareCommand(userArgs []string) ([]string, error) {
	if len(userArgs) == 0 {
		return []string{binary}, nil
	}
	if userArgs[0] == binary {
		return userArgs, nil
	}
	return append([]string{binary}, userArgs...), nil
}

// Health reports readiness based on whether the hermes binary is on PATH (there
// is no standard Hermes health endpoint to probe).
func (a *Adapter) Health(ctx context.Context) harness.Health {
	if _, err := exec.LookPath(binary); err != nil {
		return harness.Health{Status: "not_found", Ready: false, Message: "hermes binary not found on PATH"}
	}
	return harness.Health{Status: "ready", Ready: true, Message: "hermes binary present"}
}
