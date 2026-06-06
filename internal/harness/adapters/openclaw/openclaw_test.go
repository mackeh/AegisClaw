package openclaw

import (
	"context"
	"testing"
)

func TestOpenClawAdapterBasics(t *testing.T) {
	a := New(t.TempDir())
	if a.Name() != "openclaw" {
		t.Fatalf("name = %q", a.Name())
	}

	// Declares the OpenClaw API key as a scoped secret.
	var hasKey bool
	for _, s := range a.DefaultWiring().Secrets {
		if s.SecretName == "OPENCLAW_API_KEY" {
			hasKey = true
		}
	}
	if !hasKey {
		t.Fatal("expected OPENCLAW_API_KEY scoped secret")
	}

	// Declares chat-channel ingress sources.
	if len(a.IngressSources()) == 0 {
		t.Fatal("expected chat-channel ingress sources")
	}
	for _, src := range a.IngressSources() {
		if src.Kind != "chat-channel" {
			t.Fatalf("expected chat-channel ingress, got %q", src.Kind)
		}
	}

	// Ships a non-empty default egress allowlist.
	if len(a.DefaultEgressDomains()) == 0 {
		t.Fatal("expected default egress domains")
	}
}

func TestOpenClawPrepareCommand(t *testing.T) {
	a := New(t.TempDir())
	if got, _ := a.PrepareCommand(nil); len(got) != 1 || got[0] != "openclaw" {
		t.Fatalf("empty args should default to [openclaw], got %v", got)
	}
	if got, _ := a.PrepareCommand([]string{"up"}); len(got) != 2 || got[0] != "openclaw" || got[1] != "up" {
		t.Fatalf("subcommand should be prefixed, got %v", got)
	}
	if got, _ := a.PrepareCommand([]string{"openclaw", "up"}); len(got) != 2 {
		t.Fatalf("explicit binary should pass through, got %v", got)
	}
}

func TestOpenClawHealthWithoutConfig(t *testing.T) {
	// No adapter config in an empty dir → not ready, but must not panic.
	h := New(t.TempDir()).Health(context.Background())
	if h.Ready {
		t.Fatalf("expected not-ready health without config, got %+v", h)
	}
}
