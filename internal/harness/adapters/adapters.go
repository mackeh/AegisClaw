// Package adapters wires the built-in agent adapters into a harness.Registry.
// It is the single source of truth for which agents the harness supports, used
// by both the CLI (`aegisclaw harness`) and the dashboard server.
package adapters

import (
	"github.com/mackeh/AegisClaw/internal/harness"
	"github.com/mackeh/AegisClaw/internal/harness/adapters/generic"
	"github.com/mackeh/AegisClaw/internal/harness/adapters/hermes"
	"github.com/mackeh/AegisClaw/internal/harness/adapters/openclaw"
)

// Default returns a registry with the built-in adapters registered. cfgDir is
// passed to adapters that need it (e.g. OpenClaw's health probe).
func Default(cfgDir string) *harness.Registry {
	reg := harness.NewRegistry()
	reg.Register(generic.New())
	reg.Register(openclaw.New(cfgDir))
	reg.Register(hermes.New())
	return reg
}
