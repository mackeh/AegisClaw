// Package policy implements the security policy engine for AegisClaw using OPA/Rego.
package policy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mackeh/AegisClaw/internal/scope"
	"github.com/open-policy-agent/opa/rego"
)

// Decision represents the outcome of a policy evaluation
type Decision int

const (
	Allow Decision = iota
	Deny
	RequireApproval
)

func (d Decision) String() string {
	switch d {
	case Allow:
		return "allow"
	case Deny:
		return "deny"
	case RequireApproval:
		return "require_approval"
	default:
		return "unknown"
	}
}

// Engine evaluates policy rules against scope requests using OPA
type Engine struct {
	query rego.PreparedEvalQuery
}

// NewEngine creates a new policy engine from a Rego policy string
func NewEngine(ctx context.Context, policyContent string) (*Engine, error) {
	r := rego.New(
		rego.Query("data.aegisclaw.policy.decision"),
		rego.Module("policy.rego", policyContent),
	)

	query, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare rego query: %w", err)
	}

	return &Engine{query: query}, nil
}

// LoadPolicy loads a policy from the specified path (rego file)
func LoadPolicy(ctx context.Context, path string) (*Engine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}
	return NewEngine(ctx, string(data))
}

// LoadDefaultPolicy loads the policy from the default config directory
func LoadDefaultPolicy(ctx context.Context) (*Engine, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	// Try loading policy.rego
	path := filepath.Join(home, ".aegisclaw", "policy.rego")
	if _, err := os.Stat(path); err == nil {
		return LoadPolicy(ctx, path)
	}
	
	// Fallback to a safe default if file not found (or could embed default policy)
	defaultPolicy := `
package aegisclaw.policy
import rego.v1
default decision = "require_approval"
`
	return NewEngine(ctx, defaultPolicy)
}

// Evaluate checks a scope request against the policy and returns a decision
func (e *Engine) Evaluate(ctx context.Context, s scope.Scope) (Decision, error) {
	input := map[string]interface{}{
		"scope": map[string]interface{}{
			"name":     s.Name,
			"resource": s.Resource,
			"risk":     s.RiskLevel.String(),
		},
	}

	results, err := e.query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return RequireApproval, err
	}

	if len(results) == 0 || len(results[0].Expressions) == 0 {
		// No decision matched, return safe default
		return RequireApproval, nil
	}

	decisionStr, ok := results[0].Expressions[0].Value.(string)
	if !ok {
		return RequireApproval, fmt.Errorf("policy returned non-string decision")
	}

	return parseDecision(decisionStr), nil
}

// EvaluateRequest evaluates all scopes in a request
func (e *Engine) EvaluateRequest(ctx context.Context, req scope.ScopeRequest) (Decision, []scope.Scope, error) {
	requiresApproval := []scope.Scope{}
	
	for _, s := range req.Scopes {
		decision, err := e.Evaluate(ctx, s)
		if err != nil {
			// Fail secure on error
			return RequireApproval, []scope.Scope{s}, err
		}
		
		switch decision {
		case Deny:
			return Deny, []scope.Scope{s}, nil
		case RequireApproval:
			requiresApproval = append(requiresApproval, s)
		}
	}

	if len(requiresApproval) > 0 {
		return RequireApproval, requiresApproval, nil
	}

	return Allow, nil, nil
}

func parseDecision(s string) Decision {
	switch s {
	case "allow":
		return Allow
	case "deny":
		return Deny
	case "require_approval":
		return RequireApproval
	default:
		return RequireApproval // Safe default
	}
}