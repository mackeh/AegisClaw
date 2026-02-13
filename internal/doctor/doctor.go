// Package doctor provides health checks for the AegisClaw runtime environment.
package doctor

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/mackeh/AegisClaw/internal/audit"
	"github.com/mackeh/AegisClaw/internal/config"
	"github.com/mackeh/AegisClaw/internal/openclaw"
)

// Status represents the result of a health check.
type Status int

const (
	StatusPass Status = iota
	StatusWarn
	StatusFail
)

// Result holds the outcome of a single health check.
type Result struct {
	Name   string
	Status Status
	Detail string
	Fix    string // suggested remediation
}

// RunAll executes all health checks and returns the results.
func RunAll() []Result {
	cfgDir, err := config.DefaultConfigDir()
	if err != nil {
		return []Result{{
			Name:   "Config directory",
			Status: StatusFail,
			Detail: err.Error(),
			Fix:    "Run: aegisclaw init",
		}}
	}

	checks := []func(string) Result{
		checkConfigDir,
		checkConfig,
		checkOpenClawAdapter,
		checkDocker,
		checkGVisor,
		checkPolicy,
		checkSecrets,
		checkAuditLog,
		checkDiskSpace,
	}

	results := make([]Result, 0, len(checks))
	for _, check := range checks {
		results = append(results, check(cfgDir))
	}
	return results
}

func checkConfigDir(cfgDir string) Result {
	info, err := os.Stat(cfgDir)
	if err != nil {
		return Result{
			Name:   "Config directory",
			Status: StatusFail,
			Detail: "~/.aegisclaw not found",
			Fix:    "Run: aegisclaw init",
		}
	}
	if !info.IsDir() {
		return Result{
			Name:   "Config directory",
			Status: StatusFail,
			Detail: "~/.aegisclaw exists but is not a directory",
			Fix:    "Remove the file and run: aegisclaw init",
		}
	}
	return Result{
		Name:   "Config directory",
		Status: StatusPass,
		Detail: cfgDir,
	}
}

func checkConfig(cfgDir string) Result {
	configPath := filepath.Join(cfgDir, "config.yaml")
	_, err := config.Load(configPath)
	if err != nil {
		return Result{
			Name:   "Configuration",
			Status: StatusFail,
			Detail: err.Error(),
			Fix:    "Run: aegisclaw init",
		}
	}
	return Result{
		Name:   "Configuration",
		Status: StatusPass,
		Detail: configPath,
	}
}

func checkDocker(cfgDir string) Result {
	out, err := exec.Command("docker", "info", "--format", "{{.ServerVersion}}").Output()
	if err != nil {
		return Result{
			Name:   "Docker daemon",
			Status: StatusFail,
			Detail: "Docker not found or not running",
			Fix:    "Install Docker: https://docs.docker.com/get-docker/",
		}
	}
	version := strings.TrimSpace(string(out))
	return Result{
		Name:   "Docker daemon",
		Status: StatusPass,
		Detail: fmt.Sprintf("running (v%s)", version),
	}
}

func checkGVisor(cfgDir string) Result {
	out, err := exec.Command("runsc", "--version").Output()
	if err != nil {
		return Result{
			Name:   "gVisor runtime",
			Status: StatusWarn,
			Detail: "not installed (optional)",
			Fix:    "Install gVisor: https://gvisor.dev/docs/user_guide/install/",
		}
	}
	version := strings.TrimSpace(string(out))
	// Extract first line
	if idx := strings.IndexByte(version, '\n'); idx > 0 {
		version = version[:idx]
	}
	return Result{
		Name:   "gVisor runtime",
		Status: StatusPass,
		Detail: version,
	}
}

func checkPolicy(cfgDir string) Result {
	policyPath := filepath.Join(cfgDir, "policy.rego")
	info, err := os.Stat(policyPath)
	if err != nil {
		return Result{
			Name:   "Policy engine",
			Status: StatusFail,
			Detail: "policy.rego not found",
			Fix:    "Run: aegisclaw init",
		}
	}
	return Result{
		Name:   "Policy engine",
		Status: StatusPass,
		Detail: fmt.Sprintf("loaded (%d bytes)", info.Size()),
	}
}

func checkSecrets(cfgDir string) Result {
	secretsDir := filepath.Join(cfgDir, "secrets")
	keyFile := filepath.Join(secretsDir, "keys.txt")

	if _, err := os.Stat(secretsDir); os.IsNotExist(err) {
		return Result{
			Name:   "Secret store",
			Status: StatusWarn,
			Detail: "secrets directory not found",
			Fix:    "Run: aegisclaw secrets init",
		}
	}

	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		return Result{
			Name:   "Secret store",
			Status: StatusWarn,
			Detail: "not initialized (no keypair)",
			Fix:    "Run: aegisclaw secrets init",
		}
	}

	// Count secrets if encrypted file exists
	encFile := filepath.Join(secretsDir, "secrets.enc")
	if _, err := os.Stat(encFile); os.IsNotExist(err) {
		return Result{
			Name:   "Secret store",
			Status: StatusPass,
			Detail: "initialized (0 secrets)",
		}
	}

	return Result{
		Name:   "Secret store",
		Status: StatusPass,
		Detail: "initialized",
	}
}

func checkAuditLog(cfgDir string) Result {
	logPath := filepath.Join(cfgDir, "audit", "audit.log")

	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		return Result{
			Name:   "Audit log",
			Status: StatusPass,
			Detail: "empty (no entries yet)",
		}
	}

	entries, err := audit.ReadAll(logPath)
	if err != nil {
		return Result{
			Name:   "Audit log",
			Status: StatusFail,
			Detail: fmt.Sprintf("failed to read: %s", err),
			Fix:    "Check file permissions on ~/.aegisclaw/audit/audit.log",
		}
	}

	valid, err := audit.Verify(logPath)
	if err != nil || !valid {
		detail := "hash chain broken"
		if err != nil {
			detail = err.Error()
		}
		return Result{
			Name:   "Audit log",
			Status: StatusFail,
			Detail: fmt.Sprintf("%d entries, %s", len(entries), detail),
			Fix:    "Audit log may have been tampered with. Investigate immediately.",
		}
	}

	return Result{
		Name:   "Audit log",
		Status: StatusPass,
		Detail: fmt.Sprintf("valid (%d entries, chain intact)", len(entries)),
	}
}

func checkOpenClawAdapter(cfgDir string) Result {
	h := openclaw.CheckHealth(cfgDir)

	result := Result{
		Name:   "OpenClaw adapter",
		Detail: h.Message,
	}

	switch h.Status {
	case openclaw.StatusConnected:
		result.Status = StatusPass
		result.Detail = fmt.Sprintf("reachable (%d, %dms), adapter ready", h.HTTPStatus, h.LatencyMS)
	case openclaw.StatusNotConfigured:
		result.Status = StatusWarn
		result.Fix = "Create ~/.aegisclaw/adapters/openclaw.yaml (see README OpenClaw integration)"
	case openclaw.StatusDisabled:
		result.Status = StatusWarn
		result.Fix = "Set enabled: true to enable OpenClaw integration"
	case openclaw.StatusInvalidConfig:
		result.Status = StatusFail
		result.Fix = "Fix YAML syntax in ~/.aegisclaw/adapters/openclaw.yaml"
	case openclaw.StatusInvalidEP:
		result.Status = StatusFail
		result.Fix = "Set endpoint to a valid HTTP/HTTPS URL (for example http://127.0.0.1:8080)"
	case openclaw.StatusUnreachable:
		result.Status = StatusWarn
		result.Fix = "Start OpenClaw service or verify adapter endpoint/port"
	case openclaw.StatusConfigError:
		result.Status = StatusFail
		result.Fix = "Ensure ~/.aegisclaw/adapters/openclaw.yaml is readable"
	default:
		result.Status = StatusWarn
		result.Fix = "Check OpenClaw adapter config and connectivity"
	}

	if h.Status == openclaw.StatusDegraded {
		result.Status = StatusWarn
		switch {
		case !h.SecretConfigured:
			result.Fix = "Set api_key_secret in adapter config and run: aegisclaw secrets set <KEY> <VALUE>"
		case !h.SecretPresent:
			result.Fix = "Set the configured API key in secrets: aegisclaw secrets set <KEY> <VALUE>"
		default:
			result.Fix = "Check OpenClaw endpoint health and authentication configuration"
		}
		result.Detail = fmt.Sprintf("reachable (%d, %dms), %s", h.HTTPStatus, h.LatencyMS, h.Message)
	}

	return result
}
