package main

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config represents the AegisClaw configuration
type Config struct {
	Version string `yaml:"version"`
	Agent   struct {
		Name    string `yaml:"name"`
		Enabled bool   `yaml:"enabled"`
	} `yaml:"agent"`
	Security struct {
		SandboxBackend  string `yaml:"sandbox_backend"`
		RequireApproval bool   `yaml:"require_approval"`
		AuditEnabled    bool   `yaml:"audit_enabled"`
	} `yaml:"security"`
	Network struct {
		DefaultDeny bool     `yaml:"default_deny"`
		Allowlist   []string `yaml:"allowlist"`
	} `yaml:"network"`
}

func defaultConfig() *Config {
	cfg := &Config{
		Version: "0.1",
	}
	cfg.Agent.Name = "default"
	cfg.Agent.Enabled = true
	cfg.Security.SandboxBackend = "docker"
	cfg.Security.RequireApproval = true
	cfg.Security.AuditEnabled = true
	cfg.Network.DefaultDeny = true
	cfg.Network.Allowlist = []string{}
	return cfg
}

func runInit() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	configDir := filepath.Join(home, ".aegisclaw")
	
	// Create config directory
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}
	fmt.Printf("✅ Created config directory: %s\n", configDir)

	// Create default config
	configPath := filepath.Join(configDir, "config.yaml")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		cfg := defaultConfig()
		data, err := yaml.Marshal(cfg)
		if err != nil {
			return fmt.Errorf("failed to marshal config: %w", err)
		}
		if err := os.WriteFile(configPath, data, 0600); err != nil {
			return fmt.Errorf("failed to write config: %w", err)
		}
		fmt.Printf("✅ Created default config: %s\n", configPath)
	} else {
		fmt.Printf("⏭️  Config already exists: %s\n", configPath)
	}

	// Create default policy
	policyPath := filepath.Join(configDir, "policy.yaml")
	if _, err := os.Stat(policyPath); os.IsNotExist(err) {
		defaultPolicy := `# AegisClaw Security Policy
version: "0.1"

rules:
  # Critical: Always require approval
  - scope: "shell.exec"
    decision: require_approval
    risk: critical

  # High: Require approval by default
  - scope: "files.write"
    decision: require_approval
    risk: high

  - scope: "email.send"
    decision: require_approval
    risk: high

  - scope: "secrets.access"
    decision: require_approval
    risk: high

  # Medium: Allow with constraints
  - scope: "http.request"
    decision: allow
    risk: medium
    constraints:
      domains: []  # Add allowed domains

  # Low: Allow by default
  - scope: "files.read"
    decision: allow
    risk: low
    constraints:
      paths:
        - "${HOME}/workspace"
`
		if err := os.WriteFile(policyPath, []byte(defaultPolicy), 0600); err != nil {
			return fmt.Errorf("failed to write policy: %w", err)
		}
		fmt.Printf("✅ Created default policy: %s\n", policyPath)
	} else {
		fmt.Printf("⏭️  Policy already exists: %s\n", policyPath)
	}

	// Create audit log directory
	auditDir := filepath.Join(configDir, "audit")
	if err := os.MkdirAll(auditDir, 0700); err != nil {
		return fmt.Errorf("failed to create audit directory: %w", err)
	}
	fmt.Printf("✅ Created audit directory: %s\n", auditDir)

	// Create secrets directory
	secretsDir := filepath.Join(configDir, "secrets")
	if err := os.MkdirAll(secretsDir, 0700); err != nil {
		return fmt.Errorf("failed to create secrets directory: %w", err)
	}
	fmt.Printf("✅ Created secrets directory: %s\n", secretsDir)

	fmt.Println("\n🦅 AegisClaw initialized successfully!")
	fmt.Println("\nNext steps:")
	fmt.Println("  1. Edit ~/.aegisclaw/policy.yaml to customize security rules")
	fmt.Println("  2. Run 'aegisclaw secrets set OPENAI_API_KEY' to add secrets")
	fmt.Println("  3. Run 'aegisclaw run' to start the runtime")

	return nil
}
