package hermes

import (
	"testing"

	"github.com/mackeh/AegisClaw/internal/harness"
)

func TestHermesAdapterBasics(t *testing.T) {
	a := New()
	if a.Name() != "hermes" {
		t.Fatalf("name = %q", a.Name())
	}
	if !a.RequiresSandbox() {
		t.Fatal("hermes must require the sandbox (it executes its own code)")
	}
	// Implements the optional SandboxRequirer interface.
	var _ harness.SandboxRequirer = a

	// Declares the self-generated-skills ingress surface.
	var hasSkills bool
	for _, src := range a.IngressSources() {
		if src.Name == "self-generated-skills" && src.Kind == "filesystem" {
			hasSkills = true
		}
	}
	if !hasSkills {
		t.Fatal("expected self-generated-skills filesystem ingress")
	}

	if len(a.DefaultEgressDomains()) == 0 {
		t.Fatal("expected default egress domains")
	}
}

func TestHermesPrepareCommand(t *testing.T) {
	a := New()
	if got, _ := a.PrepareCommand([]string{"serve"}); len(got) != 2 || got[0] != "hermes" {
		t.Fatalf("subcommand should be prefixed with hermes, got %v", got)
	}
}
