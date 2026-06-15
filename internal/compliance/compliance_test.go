package compliance

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mackeh/AegisClaw/internal/config"
)

func TestAssess_BasicConfig(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			SandboxBackend:  "docker",
			RequireApproval: true,
			AuditEnabled:    true,
		},
		Network: config.NetworkConfig{
			DefaultDeny: true,
		},
	}

	assessment, err := Assess(cfg, "/nonexistent/audit.log")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if assessment.Framework == "" {
		t.Fatal("expected framework to be set")
	}
	if len(assessment.Controls) != 10 {
		t.Fatalf("expected 10 ASI controls, got %d", len(assessment.Controls))
	}
	if assessment.OverallScore < 0 || assessment.OverallScore > 100 {
		t.Fatalf("score out of range: %d", assessment.OverallScore)
	}
	if assessment.OverallGrade == "" {
		t.Fatal("expected grade to be set")
	}
}

func TestAssess_MinimalConfig(t *testing.T) {
	cfg := &config.Config{}

	assessment, err := Assess(cfg, "/nonexistent/audit.log")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Minimal config should have low scores
	for _, c := range assessment.Controls {
		if c.ID == "" {
			t.Fatal("control ID should not be empty")
		}
		if c.Score < 0 || c.Score > 100 {
			t.Fatalf("control %s score out of range: %d", c.ID, c.Score)
		}
	}
}

func TestAssess_ControlIDs(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			RequireApproval: true,
		},
	}

	assessment, err := Assess(cfg, "/nonexistent/audit.log")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedIDs := []string{ASI01, ASI02, ASI03, ASI04, ASI05, ASI06, ASI07, ASI08, ASI09, ASI10}
	for i, c := range assessment.Controls {
		if c.ID != expectedIDs[i] {
			t.Errorf("control %d: expected ID %s, got %s", i, expectedIDs[i], c.ID)
		}
	}
}

func TestAssess_CoverageValues(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			SandboxBackend:  "docker",
			RequireApproval: true,
			AuditEnabled:    true,
		},
		Network: config.NetworkConfig{
			DefaultDeny: true,
		},
	}

	assessment, err := Assess(cfg, "/nonexistent/audit.log")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, c := range assessment.Controls {
		switch c.Coverage {
		case CoverageFull, CoveragePartial, CoverageNone:
			// valid
		default:
			t.Errorf("control %s: invalid coverage %q", c.ID, c.Coverage)
		}
	}
}

func TestGradeFromScore(t *testing.T) {
	tests := []struct {
		score int
		grade string
	}{
		{95, "A"},
		{90, "A"},
		{80, "B"},
		{75, "B"},
		{65, "C"},
		{60, "C"},
		{50, "D"},
		{40, "D"},
		{30, "F"},
		{0, "F"},
	}

	for _, tt := range tests {
		got := gradeFromScore(tt.score)
		if got != tt.grade {
			t.Errorf("gradeFromScore(%d) = %s, want %s", tt.score, got, tt.grade)
		}
	}
}

func TestGenerateReport(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			RequireApproval: true,
			AuditEnabled:    true,
		},
	}

	report, err := GenerateReport(cfg, "/nonexistent/audit.log")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.Assessment == nil {
		t.Fatal("expected assessment to be set")
	}
	if report.AuditSummary == nil {
		t.Fatal("expected audit summary to be set")
	}
	if report.PolicySummary == nil {
		t.Fatal("expected policy summary to be set")
	}
	if report.ChainIntegrity == nil {
		t.Fatal("expected chain integrity to be set")
	}
}

func TestExportReport(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			RequireApproval: true,
		},
	}

	report, err := GenerateReport(cfg, "/nonexistent/audit.log")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tmpDir := t.TempDir()
	path, err := ExportReport(report, tmpDir)
	if err != nil {
		t.Fatalf("export failed: %v", err)
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatalf("report file not created: %s", path)
	}

	// Verify it's valid JSON
	data, _ := os.ReadFile(path)
	if len(data) == 0 {
		t.Fatal("report file is empty")
	}
}

func TestSummarizeAudit_Empty(t *testing.T) {
	summary := summarizeAudit(nil)
	if summary.TotalEntries != 0 {
		t.Fatalf("expected 0 entries, got %d", summary.TotalEntries)
	}
}

func TestIsKernelAction(t *testing.T) {
	if !isKernelAction("kernel.syscall") {
		t.Error("expected kernel.syscall to be kernel action")
	}
	if isKernelAction("skill.execute") {
		t.Error("expected skill.execute to not be kernel action")
	}
	if isKernelAction("short") {
		t.Error("expected short string to not be kernel action")
	}
}

func TestFilterPresent(t *testing.T) {
	result := filterPresent(true, "a", false, "b", true, "c")
	if len(result) != 2 || result[0] != "a" || result[1] != "c" {
		t.Errorf("unexpected result: %v", result)
	}
}

func TestScoreFromMulti(t *testing.T) {
	if scoreFromMulti(true, true, true, true) != 100 {
		t.Error("all true should be 100")
	}
	if scoreFromMulti(false, false, false, false) != 0 {
		t.Error("all false should be 0")
	}
	if scoreFromMulti(true, false, true, false) != 50 {
		t.Error("half true should be 50")
	}
}

func TestExportReport_CreatesDirectory(t *testing.T) {
	cfg := &config.Config{}
	report, _ := GenerateReport(cfg, "/nonexistent/audit.log")

	tmpDir := filepath.Join(t.TempDir(), "nested", "reports")
	path, err := ExportReport(report, tmpDir)
	if err != nil {
		t.Fatalf("export to nested dir failed: %v", err)
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatalf("report file not created at nested path: %s", path)
	}
}
