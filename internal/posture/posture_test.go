package posture

import (
	"testing"

	"github.com/mackeh/AegisClaw/internal/config"
)

func TestGradeFromPct(t *testing.T) {
	tests := []struct {
		pct      int
		expected Grade
	}{
		{100, GradeA},
		{90, GradeA},
		{89, GradeB},
		{75, GradeB},
		{74, GradeC},
		{60, GradeC},
		{59, GradeD},
		{40, GradeD},
		{39, GradeF},
		{0, GradeF},
	}

	for _, tt := range tests {
		got := gradeFromPct(tt.pct)
		if got != tt.expected {
			t.Errorf("gradeFromPct(%d) = %s, want %s", tt.pct, got, tt.expected)
		}
	}
}

func TestScoreSandbox(t *testing.T) {
	tests := []struct {
		runtime  string
		expected int
	}{
		{"kata-fc", 30},
		{"kata-runtime", 25},
		{"runsc", 20},
		{"runc", 15},
		{"", 15},
	}

	for _, tt := range tests {
		cfg := &config.Config{Security: config.SecurityConfig{SandboxRuntime: tt.runtime}}
		cat := scoreSandbox(cfg)
		if cat.Points != tt.expected {
			t.Errorf("scoreSandbox(runtime=%q) = %d points, want %d", tt.runtime, cat.Points, tt.expected)
		}
		if cat.Max != 30 {
			t.Errorf("expected max 30, got %d", cat.Max)
		}
	}
}

func TestScoreNetwork(t *testing.T) {
	tests := []struct {
		name     string
		cfg      config.NetworkConfig
		expected int
	}{
		{"default-deny", config.NetworkConfig{DefaultDeny: true}, 15},
		{"allowlist", config.NetworkConfig{Allowlist: []string{"example.com"}}, 10},
		{"no-restrictions", config.NetworkConfig{}, 0},
	}

	for _, tt := range tests {
		cfg := &config.Config{Network: tt.cfg}
		cat := scoreNetwork(cfg)
		if cat.Points != tt.expected {
			t.Errorf("scoreNetwork(%s) = %d points, want %d", tt.name, cat.Points, tt.expected)
		}
	}
}

func TestScoreSecrets(t *testing.T) {
	// Non-existent directory should score 0
	cat := scoreSecrets("/nonexistent/path")
	if cat.Points != 0 {
		t.Errorf("expected 0 points for missing secrets, got %d", cat.Points)
	}
	if cat.Max != 20 {
		t.Errorf("expected max 20, got %d", cat.Max)
	}
}

func TestScorePolicy_NoFile(t *testing.T) {
	cfg := &config.Config{}
	cat := scorePolicy(cfg, "/nonexistent/path")
	if cat.Points != 0 {
		t.Errorf("expected 0 points for missing policy, got %d", cat.Points)
	}
}

func TestScoreAudit_Disabled(t *testing.T) {
	cfg := &config.Config{Security: config.SecurityConfig{AuditEnabled: false}}
	cat := scoreAudit(cfg, t.TempDir())
	if cat.Points != 0 {
		t.Errorf("expected 0 points for disabled audit, got %d", cat.Points)
	}
}
