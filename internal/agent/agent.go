package agent

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/mackeh/AegisClaw/internal/approval"
	"github.com/mackeh/AegisClaw/internal/audit"
	"github.com/mackeh/AegisClaw/internal/config"
	"github.com/mackeh/AegisClaw/internal/ebpf"
	"github.com/mackeh/AegisClaw/internal/policy"
	"github.com/mackeh/AegisClaw/internal/sandbox"
	"github.com/mackeh/AegisClaw/internal/scope"
	"github.com/mackeh/AegisClaw/internal/secrets"
	"github.com/mackeh/AegisClaw/internal/security/redactor"
	"github.com/mackeh/AegisClaw/internal/skill"
	"github.com/mackeh/AegisClaw/internal/system"
	"github.com/mackeh/AegisClaw/internal/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

// ExecutionResult holds the captured output of a skill run
type ExecutionResult struct {
	ExitCode int
	Stdout   string
	Stderr   string
}

// ExecuteSkill is a wrapper for ExecuteSkillWithStream using default outputs
func ExecuteSkill(ctx context.Context, m *skill.Manifest, cmdName string, userArgs []string) (*ExecutionResult, error) {
	return ExecuteSkillWithStream(ctx, m, cmdName, userArgs, nil, nil)
}

// ExecuteSkillWithStream handles execution with optional real-time streaming
func ExecuteSkillWithStream(ctx context.Context, m *skill.Manifest, cmdName string, userArgs []string, stdoutStream, stderrStream io.Writer) (*ExecutionResult, error) {
	if system.IsLockedDown() {
		return nil, fmt.Errorf("SECURITY LOCKDOWN: Agent is in emergency stop mode")
	}

	tr := otel.Tracer("agent")
	ctx, span := tr.Start(ctx, "ExecuteSkill")
	defer span.End()

	span.SetAttributes(
		attribute.String("skill.name", m.Name),
		attribute.String("skill.command", cmdName),
	)

	// 1. Find Command
	skillCmd, ok := m.Commands[cmdName]
	if !ok {
		return nil, fmt.Errorf("command '%s' not found in skill '%s'", cmdName, m.Name)
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
	engine, err := policy.LoadDefaultPolicy(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load policy: %w", err)
	}
	
	decision, riskyScopes, err := engine.EvaluateRequest(ctx, req)
	if err != nil {
		telemetry.PolicyDecisionsTotal.WithLabelValues("error").Inc()
		return nil, fmt.Errorf("policy evaluation failed: %w", err)
	}
	telemetry.PolicyDecisionsTotal.WithLabelValues(decision.String()).Inc()

	finalDecision := "deny"

	// 4. Enforce Decision
	switch decision {
	case policy.Deny:
		fmt.Println("❌ Policy DENIED this action.")
		return nil, fmt.Errorf("policy denied action")

	case policy.RequireApproval:
		// Check persistent approvals
		store, err := approval.NewStore()
		if err != nil {
			return nil, err
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
				return nil, err
			}

			if userDec == "deny" {
				fmt.Println("❌ User denied the request.")
				return nil, fmt.Errorf("user denied request")
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

		// Start eBPF monitoring if supported (only on Linux)
		mon := ebpf.NewMonitor(ebpf.ProbeConfig{
			TraceSyscalls: true,
			TraceFiles:    true,
			TraceNetwork:  true,
		})
		mon.OnEvent(func(e ebpf.Event) {
			_ = logger.LogKernelEvent(string(e.Type), e.Comm, e.PID, map[string]any{
				"syscall": e.Syscall,
				"path":    e.FilePath,
			})
		})
		if err := mon.Start(ctx); err == nil {
			defer mon.Stop()
			fmt.Println("🛡️  Kernel-level eBPF monitoring active.")
		}
	}

	if finalDecision != "allow" {
		return nil, fmt.Errorf("execution blocked")
	}

	// 6. Prepare Execution Environment
	finalArgs := append(skillCmd.Args, userArgs...)
	env := append([]string{}, skillCmd.Env...)

	// Inject Secrets if allowed
	var activeSecrets []string
	if finalDecision == "allow" {
		secretsDir := filepath.Join(cfgDir, "secrets")
		mgr := secrets.NewManager(secretsDir)

		for _, s := range reqScopes {
			if s.Name == "secrets.access" && s.Resource != "" {
				val, err := mgr.Get(s.Resource)
				if err == nil {
					env = append(env, fmt.Sprintf("%s=%s", s.Resource, val))
					activeSecrets = append(activeSecrets, val)
				} else {
					fmt.Printf("⚠️  Warning: Secret '%s' requested but not found.\n", s.Resource)
				}
			}
		}
	}

	// Initialize Redactor
	scrubber := redactor.New(activeSecrets...)

	// 7. Execute
	fmt.Printf("🚀 Running skill: %s\n", m.Name)

	cfg, _ := config.LoadDefault()
	runtime := ""
	if cfg != nil {
		runtime = cfg.Security.SandboxRuntime
	}

	exec, err := sandbox.NewDockerExecutor()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize executor: %w", err)
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
		AuditLogger:    logger,
		Runtime:        runtime,
	})
	if err != nil {
		telemetry.SkillExecutionsTotal.WithLabelValues(m.Name, "error").Inc()
		return nil, fmt.Errorf("execution failed: %w", err)
	}
	telemetry.SkillExecutionsTotal.WithLabelValues(m.Name, "success").Inc()

	// Capture output
	stdoutBuf := new(bytes.Buffer)
	stderrBuf := new(bytes.Buffer)

	// Stream to console, buffer, and optional streams, but REDACT first.
	stdoutWriters := []io.Writer{os.Stdout, stdoutBuf}
	if stdoutStream != nil {
		stdoutWriters = append(stdoutWriters, stdoutStream)
	}
	
	stderrWriters := []io.Writer{os.Stderr, stderrBuf}
	if stderrStream != nil {
		stderrWriters = append(stderrWriters, stderrStream)
	}

	stdoutTarget := io.MultiWriter(stdoutWriters...)
	stderrTarget := io.MultiWriter(stderrWriters...)

	safeStdout := redactor.NewRedactingWriter(stdoutTarget, scrubber)
	safeStderr := redactor.NewRedactingWriter(stderrTarget, scrubber)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(safeStdout, result.Stdout)
	}()
	
	go func() {
		defer wg.Done()
		io.Copy(safeStderr, result.Stderr)
	}()

	wg.Wait()
	
	return &ExecutionResult{
		ExitCode: result.ExitCode,
		Stdout:   stdoutBuf.String(),
		Stderr:   stderrBuf.String(),
	}, nil
}
