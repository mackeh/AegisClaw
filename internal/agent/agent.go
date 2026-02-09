package agent

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/mackeh/AegisClaw/internal/approval"
	"github.com/mackeh/AegisClaw/internal/audit"
	"github.com/mackeh/AegisClaw/internal/config"
	"github.com/mackeh/AegisClaw/internal/policy"
	"github.com/mackeh/AegisClaw/internal/sandbox"
	"github.com/mackeh/AegisClaw/internal/scope"
	"github.com/mackeh/AegisClaw/internal/secrets"
	"github.com/mackeh/AegisClaw/internal/skill"
)

// ExecuteSkill handles the end-to-end execution of a skill command
func ExecuteSkill(ctx context.Context, m *skill.Manifest, cmdName string, userArgs []string) error {
	// 1. Find Command
	skillCmd, ok := m.Commands[cmdName]
	if !ok {
		return fmt.Errorf("command '%s' not found in skill '%s'", cmdName, m.Name)
	}

	// 2. Prepare Scopes
	var reqScopes []scope.Scope
	var allowedDomains []string
	needsNetwork := false
	for _, sStr := range m.Scopes {
		s, _ := scope.Parse(sStr)
		reqScopes = append(reqScopes, s)
		if s.Name == "http.request" || s.Name == "email.send" {
			needsNetwork = true
			if s.Resource != "" {
				allowedDomains = append(allowedDomains, s.Resource)
			}
		}
	}

	req := scope.ScopeRequest{
		RequestedBy: m.Name,
		Reason:      fmt.Sprintf("Executing action '%s'", cmdName),
		Scopes:      reqScopes,
	}

	// 3. Load Policy & Evaluate
	p, err := policy.LoadDefaultPolicy()
	if err != nil {
		return fmt.Errorf("failed to load policy: %w", err)
	}
	engine := policy.NewEngine(p)
	decision, riskyScopes := engine.EvaluateRequest(req)

	finalDecision := "deny"

	// 4. Enforce Decision
	switch decision {
	case policy.Deny:
		fmt.Println("❌ Policy DENIED this action.")
		return fmt.Errorf("policy denied action")

	case policy.RequireApproval:
		// Check persistent approvals
		store, err := approval.NewStore()
		if err != nil {
			return err
		}

		allApproved := true
		for _, s := range riskyScopes {
			if store.Check(s.String()) != "always" {
				allApproved = false
				break
			}
		}

		if allApproved {
			finalDecision = "allow"
			fmt.Println("✅ Auto-approved based on previous settings.")
		} else {
			// Prompt User
			userDec, err := approval.RequestApproval(req)
			if err != nil {
				return err
			}

			if userDec == "deny" {
				fmt.Println("❌ User denied the request.")
				return fmt.Errorf("user denied request")
			}

			finalDecision = "allow"
			if userDec == "always" {
				for _, s := range riskyScopes {
					_ = store.Grant(s.String(), "always")
				}
				fmt.Println("💾 Approval saved for future requests.")
			}
		}

	case policy.Allow:
		finalDecision = "allow"
	}

	// 5. Audit Log (Pre-execution)
	cfgDir, _ := config.DefaultConfigDir()
	auditPath := filepath.Join(cfgDir, "audit", "audit.log")
	logger, err := audit.NewLogger(auditPath)
	if err == nil {
		// Log the attempt
		_ = logger.Log("skill.exec", reqScopes, finalDecision, m.Name, map[string]any{
			"command": cmdName,
			"image":   m.Image,
		})
	}

	if finalDecision != "allow" {
		return fmt.Errorf("execution blocked")
	}

	// 6. Prepare Execution Environment
	finalArgs := append(skillCmd.Args, userArgs...)
	env := append([]string{}, skillCmd.Env...)

	// Inject Secrets if allowed
	if finalDecision == "allow" {
		cfgDir, _ := config.DefaultConfigDir()
		secretsDir := filepath.Join(cfgDir, "secrets")
		mgr := secrets.NewManager(secretsDir)

		for _, s := range reqScopes {
			if s.Name == "secrets.access" && s.Resource != "" {
				val, err := mgr.Get(s.Resource)
				if err == nil {
					env = append(env, fmt.Sprintf("%s=%s", s.Resource, val))
				} else {
					fmt.Printf("⚠️  Warning: Secret '%s' requested but not found.\n", s.Resource)
				}
			}
		}
	}

	fmt.Printf("🚀 Running skill: %s\n", m.Name)

	exec, err := sandbox.NewDockerExecutor()
	if err != nil {
		return fmt.Errorf("failed to initialize executor: %w", err)
	}

	// Set a default timeout for execution
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	result, err := exec.Run(ctx, sandbox.Config{
		Image:          m.Image,
		Command:        finalArgs,
		Env:            env,
		Network:        needsNetwork,
		AllowedDomains: allowedDomains,
	})
	if err != nil {
		return fmt.Errorf("execution failed: %w", err)
	}

	// Stream output
	io.Copy(os.Stdout, result.Stdout)
	io.Copy(os.Stderr, result.Stderr)

	fmt.Printf("✅ Skill finished (exit code %d)\n", result.ExitCode)
	return nil
}