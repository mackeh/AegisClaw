package policy

import (
	"testing"

	"github.com/mackeh/AegisClaw/internal/scope"
)

func TestEvaluate(t *testing.T) {
	p := &Policy{
		Rules: []Rule{
			{
				Scope:    "files.read",
				Decision: "allow",
				Constraints: map[string]any{
					"paths": []interface{}{"/tmp", "/home/user/safe"},
				},
			},
			{
				Scope:    "shell.exec",
				Decision: "require_approval",
			},
		},
	}
	engine := NewEngine(p)

	tests := []struct {
		name     string
		scopeStr string
		want     Decision
	}{
		{"Allowed path 1", "files.read:/tmp/file.txt", Allow},
		{"Allowed path 2", "files.read:/home/user/safe/doc.md", Allow},
		{"Denied path", "files.read:/etc/passwd", RequireApproval}, // Fallback when constraint fails
		{"No resource (fail safe)", "files.read", RequireApproval}, 
		{"Always approval", "shell.exec", RequireApproval},
		{"Unknown scope", "unknown", RequireApproval},
	}

	for _, tt := range tests {
		s, _ := scope.Parse(tt.scopeStr)
		got, _ := engine.Evaluate(s)
		if got != tt.want {
			t.Errorf("Evaluate(%q) = %v, want %v", tt.scopeStr, got, tt.want)
		}
	}
}
