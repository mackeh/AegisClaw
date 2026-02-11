// Package posture calculates a security posture score for an AegisClaw installation.
package posture

import (
	"os"
	"path/filepath"

	"github.com/mackeh/AegisClaw/internal/audit"
	"github.com/mackeh/AegisClaw/internal/config"
)

// Grade represents the overall security grade.
type Grade string

const (
	GradeA Grade = "A" // 90-100
	GradeB Grade = "B" // 75-89
	GradeC Grade = "C" // 60-74
	GradeD Grade = "D" // 40-59
	GradeF Grade = "F" // 0-39
)

// Score holds the posture assessment result.
type Score struct {
	Total       int              `json:"total"`
	Max         int              `json:"max"`
	Percentage  int              `json:"percentage"`
	Grade       Grade            `json:"grade"`
	Categories  []CategoryScore  `json:"categories"`
}

// CategoryScore holds the score for a single category.
type CategoryScore struct {
	Name   string `json:"name"`
	Points int    `json:"points"`
	Max    int    `json:"max"`
	Detail string `json:"detail"`
}

// Calculate evaluates the current AegisClaw configuration and returns a score.
func Calculate() (*Score, error) {
	cfgDir, err := config.DefaultConfigDir()
	if err != nil {
		return nil, err
	}

	cfg, err := config.LoadDefault()
	if err != nil {
		return nil, err
	}

	var categories []CategoryScore

	// Sandboxing (30 points)
	categories = append(categories, scoreSandbox(cfg))

	// Secrets (20 points)
	categories = append(categories, scoreSecrets(cfgDir))

	// Policy (20 points)
	categories = append(categories, scorePolicy(cfg, cfgDir))

	// Audit (15 points)
	categories = append(categories, scoreAudit(cfg, cfgDir))

	// Network (15 points)
	categories = append(categories, scoreNetwork(cfg))

	total, max := 0, 0
	for _, c := range categories {
		total += c.Points
		max += c.Max
	}

	pct := 0
	if max > 0 {
		pct = total * 100 / max
	}

	return &Score{
		Total:      total,
		Max:        max,
		Percentage: pct,
		Grade:      gradeFromPct(pct),
		Categories: categories,
	}, nil
}

func scoreSandbox(cfg *config.Config) CategoryScore {
	cat := CategoryScore{Name: "Sandboxing", Max: 30}

	switch cfg.Security.SandboxRuntime {
	case "kata-fc":
		cat.Points = 30
		cat.Detail = "Firecracker microVM (maximum isolation)"
	case "kata-runtime":
		cat.Points = 25
		cat.Detail = "Kata Containers (VM-level isolation)"
	case "runsc":
		cat.Points = 20
		cat.Detail = "gVisor (kernel-level sandboxing)"
	default:
		cat.Points = 15
		cat.Detail = "Docker with runc (container-level isolation)"
	}

	return cat
}

func scoreSecrets(cfgDir string) CategoryScore {
	cat := CategoryScore{Name: "Secrets", Max: 20}

	keysFile := filepath.Join(cfgDir, "secrets", "keys.txt")
	if _, err := os.Stat(keysFile); err == nil {
		cat.Points = 15
		cat.Detail = "age encryption initialized"
	} else {
		cat.Detail = "secret store not initialized"
		return cat
	}

	encFile := filepath.Join(cfgDir, "secrets", "secrets.enc")
	if _, err := os.Stat(encFile); err == nil {
		cat.Points = 20
		cat.Detail = "age encryption with stored secrets"
	}

	return cat
}

func scorePolicy(cfg *config.Config, cfgDir string) CategoryScore {
	cat := CategoryScore{Name: "Policy", Max: 20}

	policyPath := filepath.Join(cfgDir, "policy.rego")
	if _, err := os.Stat(policyPath); os.IsNotExist(err) {
		cat.Detail = "no policy file found"
		return cat
	}

	cat.Points = 10
	cat.Detail = "policy loaded"

	if cfg.Security.RequireApproval {
		cat.Points = 20
		cat.Detail = "policy loaded with approval required"
	}

	return cat
}

func scoreAudit(cfg *config.Config, cfgDir string) CategoryScore {
	cat := CategoryScore{Name: "Audit", Max: 15}

	if !cfg.Security.AuditEnabled {
		cat.Detail = "audit logging disabled"
		return cat
	}

	cat.Points = 10
	cat.Detail = "audit logging enabled"

	logPath := filepath.Join(cfgDir, "audit", "audit.log")
	if valid, err := audit.Verify(logPath); err == nil && valid {
		cat.Points = 15
		cat.Detail = "audit logging enabled, chain verified"
	}

	return cat
}

func scoreNetwork(cfg *config.Config) CategoryScore {
	cat := CategoryScore{Name: "Network", Max: 15}

	if cfg.Network.DefaultDeny {
		cat.Points = 15
		cat.Detail = "default-deny egress policy"
	} else if len(cfg.Network.Allowlist) > 0 {
		cat.Points = 10
		cat.Detail = "egress allowlist configured"
	} else {
		cat.Points = 0
		cat.Detail = "no network restrictions"
	}

	return cat
}

func gradeFromPct(pct int) Grade {
	switch {
	case pct >= 90:
		return GradeA
	case pct >= 75:
		return GradeB
	case pct >= 60:
		return GradeC
	case pct >= 40:
		return GradeD
	default:
		return GradeF
	}
}
