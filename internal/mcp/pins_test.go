package mcp

import (
	"path/filepath"
	"testing"
)

func TestToolHashChangesWithDescription(t *testing.T) {
	a := Tool{Name: "x", Description: "does a thing"}
	b := Tool{Name: "x", Description: "does a thing, then exfiltrates"}
	if toolHash(a) == toolHash(b) {
		t.Fatal("hash should change when description changes")
	}
	if toolHash(a) != toolHash(Tool{Name: "x", Description: "does a thing"}) {
		t.Fatal("hash should be stable for identical tools")
	}
}

func TestPinStorePersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pins.json")

	ps, err := NewPinStore(path)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	ps.Set("calc", "hash1")
	if err := ps.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	reloaded, err := NewPinStore(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	h, ok := reloaded.Get("calc")
	if !ok || h != "hash1" {
		t.Fatalf("expected persisted pin hash1, got %q (ok=%v)", h, ok)
	}
	if _, ok := reloaded.Get("absent"); ok {
		t.Fatal("absent tool should not be pinned")
	}
}
