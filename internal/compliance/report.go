package compliance

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/mackeh/AegisClaw/internal/audit"
	"github.com/mackeh/AegisClaw/internal/config"
)

// ReportFormat specifies the output format for compliance reports.
type ReportFormat string

const (
	FormatJSON ReportFormat = "json"
)

// Report is a structured compliance report combining OWASP ASI assessment,
// audit trail summary, and policy evaluation history.
type Report struct {
	GeneratedAt    time.Time       `json:"generated_at"`
	Format         ReportFormat    `json:"format"`
	Framework      string          `json:"framework"`
	Assessment     *Assessment     `json:"assessment"`
	AuditSummary   *AuditSummary   `json:"audit_summary"`
	PolicySummary  *PolicySummary  `json:"policy_summary"`
	ChainIntegrity *ChainIntegrity `json:"chain_integrity"`
}

// AuditSummary aggregates audit log statistics.
type AuditSummary struct {
	TotalEntries   int            `json:"total_entries"`
	FirstEntry     *time.Time     `json:"first_entry,omitempty"`
	LastEntry      *time.Time     `json:"last_entry,omitempty"`
	ActionCounts   map[string]int `json:"action_counts"`
	DecisionCounts map[string]int `json:"decision_counts"`
	UniqueActors   []string       `json:"unique_actors"`
	KernelEvents   int            `json:"kernel_events"`
}

// PolicySummary aggregates policy evaluation statistics from the audit log.
type PolicySummary struct {
	TotalEvaluations int            `json:"total_evaluations"`
	AllowCount       int            `json:"allow_count"`
	DenyCount        int            `json:"deny_count"`
	ApprovalCount    int            `json:"approval_count"`
	ScopeFrequency   map[string]int `json:"scope_frequency"`
}

// ChainIntegrity holds the result of audit chain verification.
type ChainIntegrity struct {
	Valid    bool      `json:"valid"`
	Verified time.Time `json:"verified_at"`
	Error    string    `json:"error,omitempty"`
}

// GenerateReport creates a full compliance report.
func GenerateReport(cfg *config.Config, auditPath string) (*Report, error) {
	assessment, err := Assess(cfg, auditPath)
	if err != nil {
		return nil, fmt.Errorf("assessment failed: %w", err)
	}

	entries, _ := audit.ReadAll(auditPath)
	auditSummary := summarizeAudit(entries)
	policySummary := summarizePolicy(entries)

	valid, verifyErr := audit.Verify(auditPath)
	chain := &ChainIntegrity{
		Valid:    valid,
		Verified: time.Now().UTC(),
	}
	if verifyErr != nil {
		chain.Error = verifyErr.Error()
	}

	return &Report{
		GeneratedAt:    time.Now().UTC(),
		Format:         FormatJSON,
		Framework:      "OWASP Top 10 for Agentic Applications 2026",
		Assessment:     assessment,
		AuditSummary:   auditSummary,
		PolicySummary:  policySummary,
		ChainIntegrity: chain,
	}, nil
}

// ExportReport writes a compliance report to disk.
func ExportReport(report *Report, outputDir string) (string, error) {
	if err := os.MkdirAll(outputDir, 0700); err != nil {
		return "", fmt.Errorf("failed to create output directory: %w", err)
	}

	filename := fmt.Sprintf("compliance-report-%s.json", report.GeneratedAt.Format("2006-01-02T150405"))
	path := filepath.Join(outputDir, filename)

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal report: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return "", fmt.Errorf("failed to write report: %w", err)
	}

	return path, nil
}

func summarizeAudit(entries []audit.Entry) *AuditSummary {
	summary := &AuditSummary{
		TotalEntries:   len(entries),
		ActionCounts:   make(map[string]int),
		DecisionCounts: make(map[string]int),
	}

	actorSet := make(map[string]struct{})

	for i, e := range entries {
		if i == 0 {
			t := e.Timestamp
			summary.FirstEntry = &t
		}
		if i == len(entries)-1 {
			t := e.Timestamp
			summary.LastEntry = &t
		}

		summary.ActionCounts[e.Action]++
		summary.DecisionCounts[e.Decision]++

		if e.Actor != "" {
			actorSet[e.Actor] = struct{}{}
		}

		if isKernelAction(e.Action) {
			summary.KernelEvents++
		}
	}

	for actor := range actorSet {
		summary.UniqueActors = append(summary.UniqueActors, actor)
	}

	return summary
}

func summarizePolicy(entries []audit.Entry) *PolicySummary {
	summary := &PolicySummary{
		ScopeFrequency: make(map[string]int),
	}

	for _, e := range entries {
		if isKernelAction(e.Action) {
			continue
		}

		summary.TotalEvaluations++

		switch e.Decision {
		case "allow", "allowed":
			summary.AllowCount++
		case "deny", "denied":
			summary.DenyCount++
		case "require_approval", "approved":
			summary.ApprovalCount++
		}

		for _, s := range e.Scopes {
			summary.ScopeFrequency[s]++
		}
	}

	return summary
}

func isKernelAction(action string) bool {
	return len(action) > 7 && action[:7] == "kernel."
}
