package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/mackeh/AegisClaw/internal/openclaw"
	"github.com/mackeh/AegisClaw/internal/secrets"
)

func TestHandleOpenClawHealth_MethodNotAllowed(t *testing.T) {
	s := NewServer(0)
	req := httptest.NewRequest(http.MethodPost, "/api/openclaw/health", nil)
	w := httptest.NewRecorder()

	s.handleOpenClawHealth(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

func TestHandleOpenClawHealth_NotConfigured(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	s := NewServer(0)
	req := httptest.NewRequest(http.MethodGet, "/api/openclaw/health", nil)
	w := httptest.NewRecorder()
	s.handleOpenClawHealth(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var resp openclaw.Health
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Status != openclaw.StatusNotConfigured {
		t.Fatalf("expected status %q, got %q", openclaw.StatusNotConfigured, resp.Status)
	}
}

func TestHandleOpenClawHealth_Connected(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfgDir := filepath.Join(home, ".aegisclaw")

	if err := os.MkdirAll(filepath.Join(cfgDir, "adapters"), 0700); err != nil {
		t.Fatalf("mkdir adapters: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(cfgDir, "secrets"), 0700); err != nil {
		t.Fatalf("mkdir secrets: %v", err)
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	adapterConfig := "enabled: true\nendpoint: " + upstream.URL + "\napi_key_secret: OPENCLAW_API_KEY\n"
	if err := os.WriteFile(filepath.Join(cfgDir, "adapters", "openclaw.yaml"), []byte(adapterConfig), 0600); err != nil {
		t.Fatalf("write adapter config: %v", err)
	}

	mgr := secrets.NewManager(filepath.Join(cfgDir, "secrets"))
	if _, err := mgr.Init(); err != nil {
		t.Fatalf("secrets init: %v", err)
	}
	if err := mgr.Set("OPENCLAW_API_KEY", "sk-test-openclaw"); err != nil {
		t.Fatalf("set secret: %v", err)
	}

	s := NewServer(0)
	req := httptest.NewRequest(http.MethodGet, "/api/openclaw/health", nil)
	w := httptest.NewRecorder()
	s.handleOpenClawHealth(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var resp openclaw.Health
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Status != openclaw.StatusConnected {
		t.Fatalf("expected status %q, got %q (%s)", openclaw.StatusConnected, resp.Status, resp.Message)
	}
	if !resp.Ready || !resp.Connected {
		t.Fatalf("expected ready and connected, got ready=%v connected=%v", resp.Ready, resp.Connected)
	}
}
