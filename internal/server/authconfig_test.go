package server

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAuthConfigConfigured(t *testing.T) {
	tests := []struct {
		name string
		cfg  AuthConfig
		want bool
	}{
		{"disabled", AuthConfig{Enabled: false}, false},
		{"enabled but keyless locks nobody in", AuthConfig{Enabled: true}, false},
		{"disabled with keys", AuthConfig{Enabled: false, Keys: []APIKey{{Token: "t"}}}, false},
		{"enabled with keys", AuthConfig{Enabled: true, Keys: []APIKey{{Token: "t", Role: RoleAdmin}}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.configured(); got != tt.want {
				t.Errorf("configured() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLoadAuthConfigMissingFile(t *testing.T) {
	cfg, err := loadAuthConfig(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err != nil {
		t.Fatalf("missing file should not error, got %v", err)
	}
	if cfg.Enabled || cfg.configured() {
		t.Errorf("missing file should yield a disabled config, got %+v", cfg)
	}
}

func TestLoadAuthConfigValid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.yaml")
	content := "enabled: true\nkeys:\n  - name: ci\n    token: secret-token\n    role: operator\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadAuthConfig(path)
	if err != nil {
		t.Fatalf("loadAuthConfig: %v", err)
	}
	if !cfg.configured() {
		t.Fatal("expected a configured auth config")
	}
	if len(cfg.Keys) != 1 || cfg.Keys[0].Token != "secret-token" || cfg.Keys[0].Role != RoleOperator {
		t.Errorf("unexpected keys parsed: %+v", cfg.Keys)
	}
}

func TestLoadAuthConfigMalformed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.yaml")
	if err := os.WriteFile(path, []byte("enabled: : : not yaml"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAuthConfig(path); err == nil {
		t.Error("expected an error for malformed YAML")
	}
}
