package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfigDir(t *testing.T) {
	dir, err := DefaultConfigDir()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dir == "" {
		t.Fatal("expected non-empty directory")
	}
	if filepath.Base(dir) != ".aegisclaw" {
		t.Errorf("expected dir ending in .aegisclaw, got %s", dir)
	}
}

func TestLoadSave(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.yaml")

	cfg := &Config{
		Version: "0.5.0",
		Agent:   AgentConfig{Name: "test-agent", Enabled: true},
		Security: SecurityConfig{
			SandboxBackend:  "docker",
			SandboxRuntime:  "runsc",
			RequireApproval: true,
			AuditEnabled:    true,
		},
		Network: NetworkConfig{
			DefaultDeny: true,
			Allowlist:   []string{"github.com", "api.example.com"},
		},
		Registry: RegistryConfig{
			URL:       "https://registry.example.com",
			TrustKeys: []string{"key1"},
		},
		Telemetry: TelemetryConfig{
			Enabled:  true,
			Exporter: "stdout",
		},
	}

	if err := cfg.Save(path); err != nil {
		t.Fatalf("save error: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("load error: %v", err)
	}

	if loaded.Version != "0.5.0" {
		t.Errorf("expected version '0.5.0', got '%s'", loaded.Version)
	}
	if loaded.Agent.Name != "test-agent" {
		t.Errorf("expected agent name 'test-agent', got '%s'", loaded.Agent.Name)
	}
	if !loaded.Security.RequireApproval {
		t.Error("expected require_approval true")
	}
	if loaded.Security.SandboxRuntime != "runsc" {
		t.Errorf("expected runtime 'runsc', got '%s'", loaded.Security.SandboxRuntime)
	}
	if !loaded.Network.DefaultDeny {
		t.Error("expected default_deny true")
	}
	if len(loaded.Network.Allowlist) != 2 {
		t.Errorf("expected 2 allowlist entries, got %d", len(loaded.Network.Allowlist))
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "bad.yaml")
	// Use a truly unparseable YAML structure (tab in flow context)
	os.WriteFile(path, []byte("{\t\x00invalid}"), 0600)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid yaml")
	}
}

func TestSave_Permissions(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.yaml")

	cfg := &Config{Version: "1.0"}
	if err := cfg.Save(path); err != nil {
		t.Fatalf("save error: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat error: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("expected file mode 0600, got %o", perm)
	}
}

func TestConfig_Notifications(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.yaml")

	cfg := &Config{
		Version: "0.5.0",
		Notifications: []NotificationConfig{
			{Type: "webhook", URL: "https://hook.example.com", Events: []string{"lockdown"}},
			{Type: "slack", WebhookURL: "https://hooks.slack.com/services/xxx", Events: []string{"approval.pending"}},
		},
	}

	if err := cfg.Save(path); err != nil {
		t.Fatalf("save error: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("load error: %v", err)
	}

	if len(loaded.Notifications) != 2 {
		t.Errorf("expected 2 notifications, got %d", len(loaded.Notifications))
	}
	if loaded.Notifications[0].Type != "webhook" {
		t.Errorf("expected type 'webhook', got '%s'", loaded.Notifications[0].Type)
	}
}
