package openclaw

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/mackeh/AegisClaw/internal/secrets"
)

func TestCheckHealth_NotConfigured(t *testing.T) {
	cfgDir := t.TempDir()
	h := CheckHealth(cfgDir)
	if h.Status != StatusNotConfigured {
		t.Fatalf("expected %q, got %q", StatusNotConfigured, h.Status)
	}
}

func TestCheckHealth_Disabled(t *testing.T) {
	cfgDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(cfgDir, "adapters"), 0700); err != nil {
		t.Fatalf("mkdir adapters: %v", err)
	}

	data := "enabled: false\nendpoint: http://127.0.0.1:8080\napi_key_secret: OPENCLAW_API_KEY\n"
	if err := os.WriteFile(filepath.Join(cfgDir, "adapters", "openclaw.yaml"), []byte(data), 0600); err != nil {
		t.Fatalf("write adapter config: %v", err)
	}

	h := CheckHealth(cfgDir)
	if h.Status != StatusDisabled {
		t.Fatalf("expected %q, got %q", StatusDisabled, h.Status)
	}
}

func TestCheckHealth_Connected(t *testing.T) {
	cfgDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(cfgDir, "adapters"), 0700); err != nil {
		t.Fatalf("mkdir adapters: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(cfgDir, "secrets"), 0700); err != nil {
		t.Fatalf("mkdir secrets: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	data := "enabled: true\nendpoint: " + srv.URL + "\napi_key_secret: OPENCLAW_API_KEY\n"
	if err := os.WriteFile(filepath.Join(cfgDir, "adapters", "openclaw.yaml"), []byte(data), 0600); err != nil {
		t.Fatalf("write adapter config: %v", err)
	}

	mgr := secrets.NewManager(filepath.Join(cfgDir, "secrets"))
	if _, err := mgr.Init(); err != nil {
		t.Fatalf("secrets init: %v", err)
	}
	if err := mgr.Set("OPENCLAW_API_KEY", "sk-test-openclaw"); err != nil {
		t.Fatalf("set secret: %v", err)
	}

	h := CheckHealth(cfgDir)
	if h.Status != StatusConnected {
		t.Fatalf("expected %q, got %q (%s)", StatusConnected, h.Status, h.Message)
	}
	if !h.Ready || !h.Connected || !h.SecretPresent {
		t.Fatalf("expected ready+connected+secret_present, got ready=%v connected=%v secret_present=%v", h.Ready, h.Connected, h.SecretPresent)
	}
}
