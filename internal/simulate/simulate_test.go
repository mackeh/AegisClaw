package simulate

import (
	"context"
	"testing"

	"github.com/mackeh/AegisClaw/internal/skill"
)

func TestRun_BasicSkill(t *testing.T) {
	m := &skill.Manifest{
		Name:    "test-skill",
		Version: "1.0.0",
		Image:   "alpine:latest",
		Scopes:  []string{"files.read:/tmp"},
		Commands: map[string]skill.Command{
			"test": {Args: []string{"echo", "hello"}},
		},
	}

	report, err := Run(context.Background(), m)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.SkillName != "test-skill" {
		t.Errorf("expected skill name 'test-skill', got '%s'", report.SkillName)
	}
	if report.RiskLevel == "" {
		t.Error("expected non-empty risk level")
	}
	if len(report.Commands) != 1 {
		t.Errorf("expected 1 command, got %d", len(report.Commands))
	}
}

func TestRun_UnsignedWarning(t *testing.T) {
	m := &skill.Manifest{
		Name:    "unsigned",
		Version: "1.0.0",
		Image:   "alpine:latest",
		Scopes:  []string{"files.read:/tmp"},
		Commands: map[string]skill.Command{
			"test": {Args: []string{"echo"}},
		},
	}

	report, err := Run(context.Background(), m)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, w := range report.Warnings {
		if w == "skill manifest is unsigned" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected unsigned warning")
	}
}

func TestRun_NoScopes(t *testing.T) {
	m := &skill.Manifest{
		Name:    "no-scopes",
		Version: "1.0.0",
		Image:   "alpine:latest",
		Commands: map[string]skill.Command{
			"test": {Args: []string{"echo"}},
		},
	}

	report, err := Run(context.Background(), m)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, w := range report.Warnings {
		if w == "no scopes declared — skill may lack necessary permissions" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected no-scopes warning")
	}
}

func TestRun_NetworkScope(t *testing.T) {
	m := &skill.Manifest{
		Name:    "net-skill",
		Version: "1.0.0",
		Image:   "alpine:latest",
		Scopes:  []string{"http.request:api.example.com"},
		Commands: map[string]skill.Command{
			"fetch": {Args: []string{"curl"}},
		},
	}

	report, err := Run(context.Background(), m)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(report.NetworkAccess) == 0 {
		t.Error("expected network access to be detected")
	}
}

func TestRun_FileScope(t *testing.T) {
	m := &skill.Manifest{
		Name:    "file-skill",
		Version: "1.0.0",
		Image:   "alpine:latest",
		Scopes:  []string{"files.read:/data", "files.write:/output"},
		Commands: map[string]skill.Command{
			"process": {Args: []string{"cat"}},
		},
	}

	report, err := Run(context.Background(), m)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(report.FileAccess) != 2 {
		t.Errorf("expected 2 file access entries, got %d", len(report.FileAccess))
	}
}

func TestRun_DefaultPlatform(t *testing.T) {
	m := &skill.Manifest{
		Name:    "default-platform",
		Version: "1.0.0",
		Image:   "alpine:latest",
		Commands: map[string]skill.Command{
			"test": {Args: []string{"echo"}},
		},
	}

	report, err := Run(context.Background(), m)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.Platform != "docker" {
		t.Errorf("expected default platform 'docker', got '%s'", report.Platform)
	}
}

func TestRiskLabel(t *testing.T) {
	tests := []struct {
		label    string
		expected string
	}{
		{riskLabel(0), "low"},
		{riskLabel(1), "medium"},
		{riskLabel(2), "high"},
		{riskLabel(3), "critical"},
		{riskLabel(99), "unknown"},
	}

	for _, tt := range tests {
		if tt.label != tt.expected {
			t.Errorf("expected %s, got %s", tt.expected, tt.label)
		}
	}
}
