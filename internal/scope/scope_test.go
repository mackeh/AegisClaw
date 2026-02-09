package scope

import (
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		input    string
		wantName string
		wantRes  string
		wantRisk Risk
	}{
		{"shell.exec", "shell.exec", "", RiskCritical},
		{"files.read:/home/user", "files.read", "/home/user", RiskLow},
		{"unknown.scope", "unknown.scope", "", RiskMedium},
		{"files.write:/etc/passwd", "files.write", "/etc/passwd", RiskHigh},
	}

	for _, tt := range tests {
		got, _ := Parse(tt.input)
		if got.Name != tt.wantName {
			t.Errorf("Parse(%q).Name = %q, want %q", tt.input, got.Name, tt.wantName)
		}
		if got.Resource != tt.wantRes {
			t.Errorf("Parse(%q).Resource = %q, want %q", tt.input, got.Resource, tt.wantRes)
		}
		if got.RiskLevel != tt.wantRisk {
			t.Errorf("Parse(%q).RiskLevel = %v, want %v", tt.input, got.RiskLevel, tt.wantRisk)
		}
	}
}
