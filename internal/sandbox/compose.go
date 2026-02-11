package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/mackeh/AegisClaw/internal/audit"
)

// ComposeService describes per-service scopes in a compose skill.
type ComposeService struct {
	Scopes []string `yaml:"scopes"`
}

// ComposeConfig holds configuration for a multi-container skill execution.
type ComposeConfig struct {
	ComposeFile string                    // Path to docker-compose.yml
	SkillName   string                    // For labeling and network naming
	Services    map[string]ComposeService // Per-service scope declarations
	Env         []string                  // Environment variables injected into all services
	AuditLogger *audit.Logger
}

// ComposeResult holds combined output from a compose run.
type ComposeResult struct {
	ExitCode int
	Output   string
}

// ComposeExecutor manages multi-container skill execution via docker compose.
type ComposeExecutor struct{}

// NewComposeExecutor creates a new ComposeExecutor.
func NewComposeExecutor() *ComposeExecutor {
	return &ComposeExecutor{}
}

// Run starts a docker compose stack with an isolated network and security constraints.
func (e *ComposeExecutor) Run(ctx context.Context, cfg ComposeConfig) (*ComposeResult, error) {
	// Validate compose file exists
	if _, err := os.Stat(cfg.ComposeFile); err != nil {
		return nil, fmt.Errorf("compose file not found: %w", err)
	}

	networkName := fmt.Sprintf("aegisclaw-%s-%s", cfg.SkillName, generateRandomString(8))

	// 1. Create isolated Docker network
	if err := createNetwork(ctx, networkName); err != nil {
		return nil, fmt.Errorf("failed to create network: %w", err)
	}
	defer removeNetwork(ctx, networkName)

	// 2. Build environment
	envVars := append(os.Environ(), cfg.Env...)
	envVars = append(envVars,
		fmt.Sprintf("AEGISCLAW_NETWORK=%s", networkName),
	)

	// 3. Prepare compose command
	composeDir := filepath.Dir(cfg.ComposeFile)
	composeFile := filepath.Base(cfg.ComposeFile)

	args := []string{
		"compose",
		"-f", composeFile,
		"-p", fmt.Sprintf("aegisclaw-%s", cfg.SkillName),
		"up",
		"--abort-on-container-exit",
		"--remove-orphans",
	}

	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Dir = composeDir
	cmd.Env = envVars

	// 4. Capture output
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// 5. Log to audit trail
	if cfg.AuditLogger != nil {
		cfg.AuditLogger.Log("compose.exec", nil, "allow", cfg.SkillName, map[string]any{
			"compose_file": cfg.ComposeFile,
			"network":      networkName,
			"services":     serviceNames(cfg.Services),
		})
	}

	// 6. Run
	err := cmd.Run()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return nil, fmt.Errorf("compose execution failed: %w\nstderr: %s", err, stderr.String())
		}
	}

	// 7. Cleanup: tear down the stack
	downArgs := []string{
		"compose",
		"-f", composeFile,
		"-p", fmt.Sprintf("aegisclaw-%s", cfg.SkillName),
		"down",
		"--volumes",
		"--remove-orphans",
	}
	downCmd := exec.CommandContext(context.Background(), "docker", downArgs...)
	downCmd.Dir = composeDir
	downCmd.Env = envVars
	downCmd.Stdout = io.Discard
	downCmd.Stderr = io.Discard
	downCmd.Run()

	return &ComposeResult{
		ExitCode: exitCode,
		Output:   stdout.String() + stderr.String(),
	}, nil
}

func createNetwork(ctx context.Context, name string) error {
	cmd := exec.CommandContext(ctx, "docker", "network", "create", "--internal", name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, string(out))
	}
	return nil
}

func removeNetwork(ctx context.Context, name string) {
	cmd := exec.CommandContext(ctx, "docker", "network", "rm", name)
	cmd.Run()
}

func serviceNames(services map[string]ComposeService) []string {
	names := make([]string, 0, len(services))
	for name := range services {
		names = append(names, name)
	}
	return names
}

// IsComposeAvailable checks if docker compose is available on the system.
func IsComposeAvailable() bool {
	cmd := exec.Command("docker", "compose", "version")
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "Docker Compose")
}
