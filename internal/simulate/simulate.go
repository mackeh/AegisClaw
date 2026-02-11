// Package simulate provides dry-run skill analysis without execution.
// It predicts behaviour based on the manifest, evaluates policy,
// and reports expected scope usage and risk.
package simulate

import (
	"context"
	"fmt"
	"strings"

	"github.com/mackeh/AegisClaw/internal/policy"
	"github.com/mackeh/AegisClaw/internal/scope"
	"github.com/mackeh/AegisClaw/internal/skill"
)

// Report holds the results of a skill simulation.
type Report struct {
	SkillName     string          `json:"skill_name"`
	Version       string          `json:"version"`
	Image         string          `json:"image"`
	Platform      string          `json:"platform"`
	Commands      []string        `json:"commands"`
	Scopes        []ScopeAnalysis `json:"scopes"`
	NetworkAccess []string        `json:"network_access"`
	FileAccess    []string        `json:"file_access"`
	RiskLevel     string          `json:"risk_level"` // low, medium, high, critical
	PolicyDecision string         `json:"policy_decision"`
	Warnings      []string        `json:"warnings,omitempty"`
}

// ScopeAnalysis describes a single scope declaration.
type ScopeAnalysis struct {
	Raw      string `json:"raw"`
	Name     string `json:"name"`
	Resource string `json:"resource"`
	Risk     string `json:"risk"`
}

// Run performs a dry-run analysis of a skill manifest.
func Run(ctx context.Context, m *skill.Manifest) (*Report, error) {
	report := &Report{
		SkillName: m.Name,
		Version:   m.Version,
		Image:     m.Image,
		Platform:  m.Platform,
	}

	if report.Platform == "" {
		report.Platform = "docker"
	}

	// List commands
	for name := range m.Commands {
		report.Commands = append(report.Commands, name)
	}

	// Analyse scopes
	highestRisk := scope.RiskLow
	for _, sStr := range m.Scopes {
		s, err := scope.Parse(sStr)
		if err != nil {
			report.Warnings = append(report.Warnings, fmt.Sprintf("invalid scope: %s", sStr))
			continue
		}

		riskLabel := riskLabel(s.RiskLevel)
		report.Scopes = append(report.Scopes, ScopeAnalysis{
			Raw:      sStr,
			Name:     s.Name,
			Resource: s.Resource,
			Risk:     riskLabel,
		})

		if s.RiskLevel > highestRisk {
			highestRisk = s.RiskLevel
		}

		// Categorize by type
		switch {
		case s.Name == "http.request" || s.Name == "email.send" || strings.HasPrefix(s.Name, "net."):
			target := s.Resource
			if target == "" {
				target = "(any)"
			}
			report.NetworkAccess = append(report.NetworkAccess, target)
		case strings.HasPrefix(s.Name, "files."):
			path := s.Resource
			if path == "" {
				path = "(any)"
			}
			report.FileAccess = append(report.FileAccess, fmt.Sprintf("%s:%s", s.Name, path))
		}
	}

	report.RiskLevel = riskLabel(highestRisk)

	// Check for warnings
	if m.Signature == "" {
		report.Warnings = append(report.Warnings, "skill manifest is unsigned")
	}
	if len(m.Scopes) == 0 {
		report.Warnings = append(report.Warnings, "no scopes declared — skill may lack necessary permissions")
	}

	// Evaluate policy
	report.PolicyDecision = evaluatePolicy(ctx, m)

	return report, nil
}

func evaluatePolicy(ctx context.Context, m *skill.Manifest) string {
	engine, err := policy.LoadDefaultPolicy(ctx)
	if err != nil {
		return "unknown (policy not loaded)"
	}

	for _, sStr := range m.Scopes {
		s, err := scope.Parse(sStr)
		if err != nil {
			continue
		}
		decision, err := engine.Evaluate(ctx, s)
		if err != nil {
			continue
		}
		switch decision {
		case policy.Deny:
			return "deny"
		case policy.RequireApproval:
			return "require_approval"
		}
	}

	if len(m.Scopes) == 0 {
		return "allow (no scopes)"
	}
	return "allow"
}

func riskLabel(r scope.Risk) string {
	switch r {
	case scope.RiskLow:
		return "low"
	case scope.RiskMedium:
		return "medium"
	case scope.RiskHigh:
		return "high"
	case scope.RiskCritical:
		return "critical"
	default:
		return "unknown"
	}
}
