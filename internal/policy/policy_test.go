package policy

import (
	"context"
	"testing"

	"github.com/mackeh/AegisClaw/internal/scope"
)

func TestEvaluate(t *testing.T) {
	policyRego := `
package aegisclaw.policy
import rego.v1

default decision = "require_approval"

decision = "allow" if {
	input.scope.name == "files.read"
	startswith(input.scope.resource, "/tmp")
}

decision = "allow" if {
	input.scope.name == "files.read"
	startswith(input.scope.resource, "/home/user/safe")
}

decision = "require_approval" if {
	input.scope.name == "shell.exec"
}
`
	ctx := context.Background()
	engine, err := NewEngine(ctx, policyRego)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	tests := []struct {
		name     string
		scopeStr string
		want     Decision
	}{
		{"Allowed path 1", "files.read:/tmp/file.txt", Allow},
		{"Allowed path 2", "files.read:/home/user/safe/doc.md", Allow},
		{"Denied path", "files.read:/etc/passwd", RequireApproval}, // Fallback
		{"No resource (fail safe)", "files.read", RequireApproval}, 
		{"Always approval", "shell.exec", RequireApproval},
		{"Unknown scope", "unknown", RequireApproval},
	}

	for _, tt := range tests {
		s, _ := scope.Parse(tt.scopeStr)
		got, err := engine.Evaluate(ctx, s)
		if err != nil {
			t.Errorf("Evaluate(%q) error = %v", tt.scopeStr, err)
			continue
		}
		if got != tt.want {
			t.Errorf("Evaluate(%q) = %v, want %v", tt.scopeStr, got, tt.want)
		}
	}
}
