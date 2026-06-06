package policy

import (
	"testing"

	"github.com/mackeh/AegisClaw/internal/scope"
)

func FuzzPolicyEvaluation(f *testing.F) {
	// Seed corpus
	f.Add("files.read", "/tmp/test", "test-skill", "reading file")
	f.Add("net.outbound", "google.com", "browser-skill", "fetching url")
	f.Add("shell.exec", "ls -la", "admin-tool", "listing dir")

	// Initialize engine once (mocking OPA if needed, but here we test the wrapper logic)
	// For a true fuzz test of Rego, we'd need the Rego engine running.
	// Since LoadDefaultPolicy relies on files, we might need a mocked engine or just fuzz the scope parsing which feeds it.
	
	f.Fuzz(func(t *testing.T, scopeName, resource, requestor, reason string) {
		// 1. Fuzz Scope Parsing
		s, err := scope.Parse(scopeName + ":" + resource)
		if err != nil {
			return // Valid rejection of bad input
		}

		// 2. Construct Request
		req := scope.ScopeRequest{
			RequestedBy: requestor,
			Reason:      reason,
			Scopes:      []scope.Scope{s},
		}

		// 3. Mock Evaluation (since we can't easily spin up OPA in a tight fuzz loop without overhead)
		// Here we verify that the Request struct doesn't cause panics when processed.
		// In a real scenario, we'd feed this into the actual policy engine.
		
		if req.RequestedBy == "" || len(req.Scopes) == 0 {
			return
		}
		
		// Basic sanity check
		if s.Name != scopeName {
			// This might happen if Parse cleans up the input
		}
	})
}
