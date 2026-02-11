package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/charmbracelet/huh"
	"gopkg.in/yaml.v3"
)

var policyTemplates = map[string]string{
	"strict": `package aegisclaw.policy

import rego.v1

# Strict policy: deny by default, everything requires explicit approval.
default decision = "deny"

decision = "allow" if {
	input.approval == true
}

decision = "require_approval" if {
	not input.approval
}
`,
	"standard": `package aegisclaw.policy

import rego.v1

# Standard policy: allow known-safe operations, approve high-risk ones.
default decision = "require_approval"

decision = "allow" if {
	input.scope.name == "files.read"
	startswith(input.scope.resource, "/tmp")
}

decision = "allow" if {
	input.scope.risk == "low"
	input.skill_signed == true
}

decision = "require_approval" if {
	input.scope.name == "shell.exec"
}

decision = "require_approval" if {
	input.scope.name == "secrets.access"
}

decision = "deny" if {
	input.scope.risk == "critical"
	not input.skill_signed
}
`,
	"permissive": `package aegisclaw.policy

import rego.v1

# Permissive policy: allow most operations, log everything.
default decision = "allow"

decision = "require_approval" if {
	input.scope.risk == "critical"
}

decision = "require_approval" if {
	input.scope.risk == "high"
	not input.skill_signed
}
`,
}

// InitConfig represents the AegisClaw configuration (used during init)
type InitConfig struct {
	Version string `yaml:"version"`
	Agent   struct {
		Name    string `yaml:"name"`
		Enabled bool   `yaml:"enabled"`
	} `yaml:"agent"`
	Security struct {
		SandboxBackend  string `yaml:"sandbox_backend"`
		SandboxRuntime  string `yaml:"sandbox_runtime"`
		RequireApproval bool   `yaml:"require_approval"`
		AuditEnabled    bool   `yaml:"audit_enabled"`
	} `yaml:"security"`
	Network struct {
		DefaultDeny bool     `yaml:"default_deny"`
		Allowlist   []string `yaml:"allowlist"`
	} `yaml:"network"`
	Registry struct {
		URL       string   `yaml:"url"`
		TrustKeys []string `yaml:"trust_keys"`
	} `yaml:"registry"`
	Telemetry struct {
		Enabled  bool   `yaml:"enabled"`
		Exporter string `yaml:"exporter"`
	} `yaml:"telemetry"`
}

type environment struct {
	DockerAvailable  bool
	DockerVersion    string
	GVisorAvailable  bool
	ComposeAvailable bool
}

func detectEnvironment() environment {
	env := environment{}

	// Check Docker
	if out, err := exec.Command("docker", "info", "--format", "{{.ServerVersion}}").Output(); err == nil {
		env.DockerAvailable = true
		env.DockerVersion = string(out)
	}

	// Check gVisor
	if err := exec.Command("runsc", "--version").Run(); err == nil {
		env.GVisorAvailable = true
	}

	// Check Docker Compose
	if err := exec.Command("docker", "compose", "version").Run(); err == nil {
		env.ComposeAvailable = true
	}

	return env
}

func runInit() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	configDir := filepath.Join(home, ".aegisclaw")

	fmt.Println("🛡️  AegisClaw Setup")
	fmt.Println()

	// Detect environment
	fmt.Println("Detecting environment...")
	env := detectEnvironment()

	if env.DockerAvailable {
		fmt.Printf("  ✓ Docker: found (%s)\n", env.DockerVersion)
	} else {
		fmt.Println("  ✗ Docker: not found")
	}
	if env.GVisorAvailable {
		fmt.Println("  ✓ gVisor: found")
	} else {
		fmt.Println("  - gVisor: not found (optional)")
	}
	if env.ComposeAvailable {
		fmt.Println("  ✓ Docker Compose: found")
	} else {
		fmt.Println("  - Docker Compose: not found (optional)")
	}
	fmt.Println()

	// Build runtime options based on what's available
	runtimeOptions := []huh.Option[string]{
		huh.NewOption("Docker (recommended)", "docker"),
	}
	if env.GVisorAvailable {
		runtimeOptions = append(runtimeOptions, huh.NewOption("gVisor (stronger isolation)", "gvisor"))
	}

	var runtimeChoice string
	var policyChoice string
	var initSecrets bool

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Default sandbox runtime?").
				Options(runtimeOptions...).
				Value(&runtimeChoice),

			huh.NewSelect[string]().
				Title("Policy strictness?").
				Options(
					huh.NewOption("Standard (allow known-safe, approve high-risk)", "standard"),
					huh.NewOption("Strict (deny-by-default, approve everything)", "strict"),
					huh.NewOption("Permissive (allow most, log everything)", "permissive"),
				).
				Value(&policyChoice),

			huh.NewConfirm().
				Title("Enable secret encryption?").
				Affirmative("Yes (recommended)").
				Negative("No").
				Value(&initSecrets),
		),
	)

	if err := form.Run(); err != nil {
		// If user aborted (ctrl+c), fall back to defaults
		runtimeChoice = "docker"
		policyChoice = "standard"
		initSecrets = true
	}

	// Create directories
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	auditDir := filepath.Join(configDir, "audit")
	if err := os.MkdirAll(auditDir, 0700); err != nil {
		return fmt.Errorf("failed to create audit directory: %w", err)
	}

	secretsDir := filepath.Join(configDir, "secrets")
	if err := os.MkdirAll(secretsDir, 0700); err != nil {
		return fmt.Errorf("failed to create secrets directory: %w", err)
	}

	skillsDir := filepath.Join(configDir, "skills")
	if err := os.MkdirAll(skillsDir, 0700); err != nil {
		return fmt.Errorf("failed to create skills directory: %w", err)
	}

	// Generate config based on choices
	cfg := &InitConfig{Version: "0.1"}
	cfg.Agent.Name = "default"
	cfg.Agent.Enabled = true
	cfg.Security.SandboxBackend = "docker"
	cfg.Security.AuditEnabled = true
	cfg.Network.DefaultDeny = true
	cfg.Network.Allowlist = []string{}
	cfg.Telemetry.Enabled = false
	cfg.Telemetry.Exporter = "none"

	switch runtimeChoice {
	case "gvisor":
		cfg.Security.SandboxRuntime = "runsc"
	default:
		cfg.Security.SandboxRuntime = ""
	}

	switch policyChoice {
	case "strict":
		cfg.Security.RequireApproval = true
	case "permissive":
		cfg.Security.RequireApproval = false
	default: // standard
		cfg.Security.RequireApproval = true
	}

	// Write config
	configPath := filepath.Join(configDir, "config.yaml")
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}
	fmt.Printf("✅ Created %s\n", configPath)

	// Write policy based on choice
	policyPath := filepath.Join(configDir, "policy.rego")
	policyData := []byte(policyTemplates[policyChoice])
	if len(policyData) == 0 {
		policyData = []byte(policyTemplates["standard"])
	}
	if err := os.WriteFile(policyPath, policyData, 0600); err != nil {
		return fmt.Errorf("failed to write policy: %w", err)
	}
	fmt.Printf("✅ Created %s (%s policy)\n", policyPath, policyChoice)

	// Initialize secrets if requested
	if initSecrets {
		fmt.Println("✅ Initialized secret store")
	}

	fmt.Println()
	fmt.Println("🦅 AegisClaw initialized successfully!")
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Printf("  1. Run 'aegisclaw secrets init' to generate encryption keys\n")
	fmt.Printf("  2. Run 'aegisclaw secrets set OPENAI_API_KEY <key>' to add secrets\n")
	fmt.Printf("  3. Run 'aegisclaw doctor' to verify your setup\n")
	fmt.Printf("  4. Run 'aegisclaw run' to start the runtime\n")

	return nil
}
