// Package openclaw provides a first-class AgentAdapter for the OpenClaw agent.
//
// OpenClaw is organised around a WebSocket gateway that fans 50+ messaging
// channels (Telegram, Discord, Slack, WhatsApp, Signal, …) into an agent
// runtime. Its defining risk surface is therefore untrusted inbound messages —
// a prime indirect-prompt-injection vector — so this adapter declares those
// channels as ingress sources and ships a default egress allowlist covering the
// channel and LLM endpoints OpenClaw needs. The adapter's Health reuses the
// existing OpenClaw adapter health probe.
package openclaw

import (
	"context"

	"github.com/mackeh/AegisClaw/internal/harness"
	"github.com/mackeh/AegisClaw/internal/openclaw"
)

const binary = "openclaw"

// Adapter is the OpenClaw agent adapter.
type Adapter struct {
	cfgDir string
}

// New returns an OpenClaw adapter that reads adapter/secret config from cfgDir.
func New(cfgDir string) *Adapter { return &Adapter{cfgDir: cfgDir} }

// Name returns the adapter identifier.
func (a *Adapter) Name() string { return "openclaw" }

// DefaultWiring declares OpenClaw's scoped secrets. The OpenClaw API key and the
// LLM provider keys are injected from the encrypted store if present; a missing
// secret is non-fatal (the supervisor logs it and continues).
func (a *Adapter) DefaultWiring() harness.Wiring {
	return harness.Wiring{
		Env: map[string]string{},
		Secrets: []harness.ScopedSecret{
			{EnvVar: "OPENCLAW_API_KEY", SecretName: "OPENCLAW_API_KEY", Scope: "secrets.access:OPENCLAW_API_KEY"},
			{EnvVar: "OPENAI_API_KEY", SecretName: "OPENAI_API_KEY", Scope: "secrets.access:OPENAI_API_KEY"},
			{EnvVar: "ANTHROPIC_API_KEY", SecretName: "ANTHROPIC_API_KEY", Scope: "secrets.access:ANTHROPIC_API_KEY"},
		},
	}
}

// IngressSources reports OpenClaw's messaging channels — untrusted inbound text
// that should be scanned for indirect prompt injection before reaching the
// model.
func (a *Adapter) IngressSources() []harness.IngressSource {
	channels := []string{"telegram", "discord", "slack", "whatsapp", "signal"}
	out := make([]harness.IngressSource, 0, len(channels))
	for _, c := range channels {
		out = append(out, harness.IngressSource{Name: c, Kind: "chat-channel"})
	}
	return out
}

// DefaultEgressDomains is the allowlist OpenClaw needs to reach its channels and
// LLM providers. Operators can extend it via network.allowlist.
func (a *Adapter) DefaultEgressDomains() []string {
	return []string{
		"api.telegram.org",
		"discord.com",
		"gateway.discord.gg",
		"slack.com",
		"api.slack.com",
		"graph.facebook.com", // WhatsApp Business API
		"api.openai.com",
		"api.anthropic.com",
	}
}

// PrepareCommand defaults the binary to "openclaw" when the user passes only a
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

// Health reuses the existing OpenClaw adapter health probe.
func (a *Adapter) Health(ctx context.Context) harness.Health {
	h := openclaw.CheckHealth(a.cfgDir)
	return harness.Health{Status: h.Status, Ready: h.Ready, Message: h.Message}
}
