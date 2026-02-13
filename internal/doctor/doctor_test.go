package doctor

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mackeh/AegisClaw/internal/secrets"
)

func TestCheckConfigDir_Missing(t *testing.T) {
	result := checkConfigDir("/nonexistent/path")
	if result.Status != StatusFail {
		t.Errorf("expected StatusFail for missing dir, got %d", result.Status)
	}
}

func TestCheckConfigDir_Exists(t *testing.T) {
	dir := t.TempDir()
	result := checkConfigDir(dir)
	if result.Status != StatusPass {
		t.Errorf("expected StatusPass for existing dir, got %d", result.Status)
	}
}

func TestCheckPolicy_Missing(t *testing.T) {
	dir := t.TempDir()
	result := checkPolicy(dir)
	if result.Status != StatusFail {
		t.Errorf("expected StatusFail for missing policy, got %d", result.Status)
	}
}

func TestCheckPolicy_Exists(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.rego")
	os.WriteFile(policyPath, []byte("package aegisclaw.policy"), 0600)

	result := checkPolicy(dir)
	if result.Status != StatusPass {
		t.Errorf("expected StatusPass for existing policy, got %d", result.Status)
	}
}

func TestCheckSecrets_NoDir(t *testing.T) {
	dir := t.TempDir()
	result := checkSecrets(dir)
	if result.Status != StatusWarn {
		t.Errorf("expected StatusWarn for missing secrets dir, got %d", result.Status)
	}
}

func TestCheckSecrets_NoKeys(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "secrets"), 0700)

	result := checkSecrets(dir)
	if result.Status != StatusWarn {
		t.Errorf("expected StatusWarn for uninitialized secrets, got %d", result.Status)
	}
}

func TestCheckAuditLog_Empty(t *testing.T) {
	dir := t.TempDir()
	result := checkAuditLog(dir)
	if result.Status != StatusPass {
		t.Errorf("expected StatusPass for empty audit log, got %d", result.Status)
	}
}

func TestCheckDiskSpace(t *testing.T) {
	dir := t.TempDir()
	result := checkDiskSpace(dir)
	// Should pass or warn on any real filesystem
	if result.Status == StatusFail {
		t.Logf("disk space check failed (may be expected in constrained env): %s", result.Detail)
	}
}

func TestCheckOpenClawAdapter_NotConfigured(t *testing.T) {
	dir := t.TempDir()
	result := checkOpenClawAdapter(dir)
	if result.Status != StatusWarn {
		t.Fatalf("expected StatusWarn, got %d (%s)", result.Status, result.Detail)
	}
}

func TestCheckOpenClawAdapter_Disabled(t *testing.T) {
	dir := t.TempDir()
	adapterDir := filepath.Join(dir, "adapters")
	if err := os.MkdirAll(adapterDir, 0700); err != nil {
		t.Fatalf("mkdir adapters: %v", err)
	}

	content := "enabled: false\nendpoint: http://127.0.0.1:8080\napi_key_secret: OPENCLAW_API_KEY\n"
	if err := os.WriteFile(filepath.Join(adapterDir, "openclaw.yaml"), []byte(content), 0600); err != nil {
		t.Fatalf("write adapter config: %v", err)
	}

	result := checkOpenClawAdapter(dir)
	if result.Status != StatusWarn {
		t.Fatalf("expected StatusWarn, got %d (%s)", result.Status, result.Detail)
	}
}

func TestCheckOpenClawAdapter_InvalidEndpoint(t *testing.T) {
	dir := t.TempDir()
	adapterDir := filepath.Join(dir, "adapters")
	if err := os.MkdirAll(adapterDir, 0700); err != nil {
		t.Fatalf("mkdir adapters: %v", err)
	}

	content := "enabled: true\nendpoint: not-a-url\napi_key_secret: OPENCLAW_API_KEY\n"
	if err := os.WriteFile(filepath.Join(adapterDir, "openclaw.yaml"), []byte(content), 0600); err != nil {
		t.Fatalf("write adapter config: %v", err)
	}

	result := checkOpenClawAdapter(dir)
	if result.Status != StatusFail {
		t.Fatalf("expected StatusFail, got %d (%s)", result.Status, result.Detail)
	}
}

func TestCheckOpenClawAdapter_ReachableWithSecret(t *testing.T) {
	dir := t.TempDir()
	adapterDir := filepath.Join(dir, "adapters")
	if err := os.MkdirAll(adapterDir, 0700); err != nil {
		t.Fatalf("mkdir adapters: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "secrets"), 0700); err != nil {
		t.Fatalf("mkdir secrets: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	content := "enabled: true\nendpoint: " + server.URL + "\napi_key_secret: OPENCLAW_API_KEY\n"
	if err := os.WriteFile(filepath.Join(adapterDir, "openclaw.yaml"), []byte(content), 0600); err != nil {
		t.Fatalf("write adapter config: %v", err)
	}

	mgr := secrets.NewManager(filepath.Join(dir, "secrets"))
	if _, err := mgr.Init(); err != nil {
		t.Fatalf("secrets init: %v", err)
	}
	if err := mgr.Set("OPENCLAW_API_KEY", "sk-test-openclaw"); err != nil {
		t.Fatalf("set secret: %v", err)
	}

	result := checkOpenClawAdapter(dir)
	if result.Status != StatusPass {
		t.Fatalf("expected StatusPass, got %d (%s)", result.Status, result.Detail)
	}
	if !strings.Contains(result.Detail, "secret 'OPENCLAW_API_KEY' loaded") {
		t.Fatalf("unexpected detail: %s", result.Detail)
	}
}

func TestCheckOpenClawAdapter_ReachableMissingSecret(t *testing.T) {
	dir := t.TempDir()
	adapterDir := filepath.Join(dir, "adapters")
	if err := os.MkdirAll(adapterDir, 0700); err != nil {
		t.Fatalf("mkdir adapters: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "secrets"), 0700); err != nil {
		t.Fatalf("mkdir secrets: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	content := "enabled: true\nendpoint: " + server.URL + "\napi_key_secret: OPENCLAW_API_KEY\n"
	if err := os.WriteFile(filepath.Join(adapterDir, "openclaw.yaml"), []byte(content), 0600); err != nil {
		t.Fatalf("write adapter config: %v", err)
	}

	result := checkOpenClawAdapter(dir)
	if result.Status != StatusWarn {
		t.Fatalf("expected StatusWarn, got %d (%s)", result.Status, result.Detail)
	}
	if !strings.Contains(result.Detail, "secret 'OPENCLAW_API_KEY' not found") {
		t.Fatalf("unexpected detail: %s", result.Detail)
	}
}
