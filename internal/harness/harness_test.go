package harness

import (
	"context"
	"strings"
	"testing"
)

// stubAdapter is a minimal adapter for exercising the registry and supervisor.
type stubAdapter struct {
	name    string
	wiring  Wiring
	ingress []IngressSource
	egress  []string
	prepare func([]string) ([]string, error)
}

func (s *stubAdapter) Name() string                    { return s.name }
func (s *stubAdapter) DefaultWiring() Wiring           { return s.wiring }
func (s *stubAdapter) IngressSources() []IngressSource { return s.ingress }
func (s *stubAdapter) DefaultEgressDomains() []string  { return s.egress }
func (s *stubAdapter) Health(context.Context) Health   { return Health{Status: "ready", Ready: true} }
func (s *stubAdapter) PrepareCommand(a []string) ([]string, error) {
	if s.prepare != nil {
		return s.prepare(a)
	}
	return a, nil
}

func TestRegistry(t *testing.T) {
	reg := NewRegistry()
	reg.Register(&stubAdapter{name: "generic"})
	reg.Register(&stubAdapter{name: "hermes"})

	if _, err := reg.Get("generic"); err != nil {
		t.Fatalf("expected generic adapter, got error: %v", err)
	}
	if _, err := reg.Get("nope"); err == nil {
		t.Fatal("expected error for unknown adapter")
	}

	names := reg.Names()
	if len(names) != 2 || names[0] != "generic" || names[1] != "hermes" {
		t.Fatalf("expected sorted [generic hermes], got %v", names)
	}

	// Re-registration replaces.
	reg.Register(&stubAdapter{name: "generic"})
	if got := reg.Names(); len(got) != 2 {
		t.Fatalf("re-registration changed count: %v", got)
	}
}

func TestBuildEnvAppliesWiringAndSecrets(t *testing.T) {
	env := HarnessEnv{
		Wiring: Wiring{
			HTTPProxy: "http://127.0.0.1:9999",
			Env:       map[string]string{"AGENT_MODE": "test"},
		},
		ResolvedSecrets: map[string]string{"API_KEY": "s3cr3t"},
	}
	got := strings.Join(buildEnv(env), "\n")

	for _, want := range []string{
		"HTTP_PROXY=http://127.0.0.1:9999",
		"https_proxy=http://127.0.0.1:9999",
		"NO_PROXY=127.0.0.1,localhost",
		"AGENT_MODE=test",
		"API_KEY=s3cr3t",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("buildEnv missing %q", want)
		}
	}
}

func TestClearSecrets(t *testing.T) {
	m := map[string]string{"A": "x", "B": "y"}
	clearSecrets(m)
	if len(m) != 0 {
		t.Fatalf("expected cleared map, got %v", m)
	}
}
