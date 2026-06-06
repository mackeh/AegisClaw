package generic

import (
	"context"
	"testing"
)

func TestGenericAdapter(t *testing.T) {
	a := New()
	if a.Name() != "generic" {
		t.Fatalf("name = %q", a.Name())
	}
	if h := a.Health(context.Background()); !h.Ready {
		t.Fatalf("generic adapter should be ready: %+v", h)
	}
	if a.IngressSources() != nil {
		t.Fatalf("generic adapter should report no ingress sources")
	}

	got, err := a.PrepareCommand([]string{"my-agent", "serve"})
	if err != nil {
		t.Fatalf("PrepareCommand: %v", err)
	}
	if len(got) != 2 || got[0] != "my-agent" || got[1] != "serve" {
		t.Fatalf("PrepareCommand should pass through, got %v", got)
	}

	if _, err := a.PrepareCommand(nil); err == nil {
		t.Fatal("expected error for empty command")
	}
}
