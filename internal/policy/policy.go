// Package policy implements the security policy engine for AegisClaw.
package policy

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/mackeh/AegisClaw/internal/scope"
	"gopkg.in/yaml.v3"
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

// Rule represents a single policy rule
type Rule struct {
	Scope       string            `yaml:"scope"`
	Decision    string            `yaml:"decision"`
	Risk        string            `yaml:"risk"`
	Constraints map[string]any    `yaml:"constraints,omitempty"`
}

// Policy represents the complete security policy
type Policy struct {
	Version string `yaml:"version"`
	Rules   []Rule `yaml:"rules"`
}

// Engine evaluates policy rules against scope requests
type Engine struct {
	policy *Policy
}

// NewEngine creates a new policy engine with the given policy
func NewEngine(policy *Policy) *Engine {
	return &Engine{policy: policy}
}

// LoadPolicy loads a policy from the specified path
func LoadPolicy(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}

	var policy Policy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("failed to parse policy: %w", err)
	}

	return &policy, nil
}

// LoadDefaultPolicy loads the policy from the default config directory
func LoadDefaultPolicy() (*Policy, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	return LoadPolicy(filepath.Join(home, ".aegisclaw", "policy.yaml"))
}

// Evaluate checks a scope request against the policy and returns a decision
func (e *Engine) Evaluate(s scope.Scope) (Decision, *Rule) {
	// Find matching rule
	for _, rule := range e.policy.Rules {
		if rule.Scope == s.Name {
			// Check constraints if present
			if len(rule.Constraints) > 0 {
				if !checkConstraints(s, rule.Constraints) {
					// Constraints failed - stricter decision needed
					// For now, fall back to RequireApproval if constraints fail
					return RequireApproval, &rule
				}
			}
			return parseDecision(rule.Decision), &rule
		}
	}

	// Default: require approval for unknown scopes
	return RequireApproval, nil
}

func checkConstraints(s scope.Scope, constraints map[string]any) bool {
	// Simple path prefix check for file scopes
	if paths, ok := constraints["paths"].([]interface{}); ok {
		// If paths are defined, resource MUST match one of them
		matched := false
		for _, p := range paths {
			if pathStr, ok := p.(string); ok {
				// Simple prefix match for now. In production, use filepath.Clean/Rel
				if s.Resource == "" || (len(s.Resource) >= len(pathStr) && s.Resource[:len(pathStr)] == pathStr) {
					matched = true
					break
				}
			}
		}
		if !matched {
			return false
		}
	}

	// Simple domain check for network scopes
	if domains, ok := constraints["domains"].([]interface{}); ok {
		matched := false
		for _, d := range domains {
			if domainStr, ok := d.(string); ok {
				if s.Resource == domainStr {
					matched = true
					break
				}
			}
		}
		if !matched {
			return false
		}
	}

	return true
}

// EvaluateRequest evaluates all scopes in a request
func (e *Engine) EvaluateRequest(req scope.ScopeRequest) (Decision, []scope.Scope) {
	requiresApproval := []scope.Scope{}
	
	for _, s := range req.Scopes {
		decision, _ := e.Evaluate(s)
		switch decision {
		case Deny:
			return Deny, []scope.Scope{s}
		case RequireApproval:
			requiresApproval = append(requiresApproval, s)
		}
	}

	if len(requiresApproval) > 0 {
		return RequireApproval, requiresApproval
	}

	return Allow, nil
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
