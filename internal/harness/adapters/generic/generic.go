// Package generic provides an AgentAdapter for any agent that honours standard
// proxy and endpoint environment variables. It applies no agent-specific
// translation, so it is the lowest-common-denominator way to run an arbitrary
// agent inside the AegisClaw envelope — the embodiment of "not only limited to"
// OpenClaw and Hermes.
package generic

import (
	"context"
	"fmt"

	"github.com/mackeh/AegisClaw/internal/harness"
)

// Adapter is the generic agent adapter.
type Adapter struct{}

// New returns a generic adapter.
func New() *Adapter { return &Adapter{} }

// Name returns the adapter identifier.
func (a *Adapter) Name() string { return "generic" }

// DefaultWiring returns an empty wiring template; the supervisor fills in the
// egress proxy. A generic agent inherits the proxy via HTTP(S)_PROXY.
func (a *Adapter) DefaultWiring() harness.Wiring {
	return harness.Wiring{Env: map[string]string{}}
}

// IngressSources reports none: the generic adapter makes no assumptions about
// where the agent reads untrusted input.
func (a *Adapter) IngressSources() []harness.IngressSource { return nil }

// DefaultEgressDomains reports none: the generic adapter does not assume any
// endpoints. The user's configured allowlist applies.
func (a *Adapter) DefaultEgressDomains() []string { return nil }

// PrepareCommand runs the user's command unchanged.
func (a *Adapter) PrepareCommand(userArgs []string) ([]string, error) {
	if len(userArgs) == 0 {
		return nil, fmt.Errorf("generic adapter requires a command to run")
	}
	return userArgs, nil
}

// Health always reports ready: the generic adapter has no agent-specific probe.
func (a *Adapter) Health(ctx context.Context) harness.Health {
	return harness.Health{Status: "ready", Ready: true, Message: "generic adapter (no agent-specific health probe)"}
}
