package harness

import (
	"context"
	"fmt"
	"io"

	"github.com/mackeh/AegisClaw/internal/audit"
	"github.com/mackeh/AegisClaw/internal/proxy"
	"github.com/mackeh/AegisClaw/internal/secrets"
)

// Supervisor launches an agent with AegisClaw's enforcement planes wired around
// it. In Phase 1 it forces the network plane (an egress proxy the agent must use
// for outbound HTTP) and injects scoped, ephemeral secrets, recording the whole
// lifecycle to the tamper-evident audit log. The tools and model planes attach
// here in later phases.
type Supervisor struct {
	// ConfigDir is the AegisClaw config directory (used for default paths).
	ConfigDir string
	// Logger receives lifecycle and plane-wiring events. May be nil.
	Logger *audit.Logger
	// Secrets resolves named secrets for injection. May be nil if the adapter
	// requests no secrets.
	Secrets *secrets.Manager
	// AllowedDomains is the egress allowlist applied to the agent's traffic.
	AllowedDomains []string
	// Launcher runs the prepared command. Defaults to ProcessLauncher.
	Launcher Launcher
	// WorkDir is the agent's working directory ("" inherits the cwd).
	WorkDir string
}

// Run prepares the command via the adapter, wires the planes, launches the
// agent, and blocks until it exits. It returns the agent's exit code. Secrets
// resolved for injection are released when Run returns.
func (s *Supervisor) Run(ctx context.Context, adapter AgentAdapter, userArgs []string, stdout, stderr io.Writer) (int, error) {
	actor := "harness:" + adapter.Name()

	command, err := adapter.PrepareCommand(userArgs)
	if err != nil {
		return -1, fmt.Errorf("adapter %s: %w", adapter.Name(), err)
	}
	if len(command) == 0 {
		return -1, fmt.Errorf("adapter %s produced an empty command", adapter.Name())
	}

	// --- Network plane: forced egress proxy -----------------------------------
	ep := proxy.NewEgressProxy(s.AllowedDomains, s.Logger)
	proxyURL, err := ep.Start()
	if err != nil {
		return -1, fmt.Errorf("failed to start egress proxy: %w", err)
	}
	defer func() { _ = ep.Stop() }()
	s.audit("harness.plane.network", "allow", actor, map[string]any{
		"plane":     string(PlaneNetwork),
		"proxy":     proxyURL,
		"allowlist": s.AllowedDomains,
	})
	if len(s.AllowedDomains) == 0 {
		fmt.Println("⚠️  Egress allowlist is empty: outbound traffic is filtered through the proxy but not restricted. Set network.allowlist to enforce default-deny.")
	}

	// --- Resolve wiring -------------------------------------------------------
	wiring := adapter.DefaultWiring()
	wiring.HTTPProxy = proxyURL

	// --- Scoped, ephemeral secret injection -----------------------------------
	resolved := make(map[string]string)
	defer clearSecrets(resolved)
	for _, sec := range wiring.Secrets {
		if s.Secrets == nil {
			s.audit("harness.secret.inject", "deny", actor, map[string]any{
				"secret": sec.SecretName, "reason": "no secret store configured",
			})
			continue
		}
		val, gerr := s.Secrets.Get(sec.SecretName)
		if gerr != nil {
			s.audit("harness.secret.inject", "deny", actor, map[string]any{
				"secret": sec.SecretName, "reason": "not found",
			})
			fmt.Printf("⚠️  Secret %q not found; agent launched without %s\n", sec.SecretName, sec.EnvVar)
			continue
		}
		resolved[sec.EnvVar] = val
		// Note: the secret *value* is never logged — only its name, target env
		// var, and the scope it was gated on.
		s.audit("harness.secret.inject", "allow", actor, map[string]any{
			"secret": sec.SecretName, "env": sec.EnvVar, "scope": sec.Scope,
		})
	}

	// --- Record ingress surface (guarded in later phases) ---------------------
	for _, src := range adapter.IngressSources() {
		s.audit("harness.ingress.register", "observed", actor, map[string]any{
			"source": src.Name, "kind": src.Kind,
		})
	}

	// --- Launch ---------------------------------------------------------------
	env := HarnessEnv{
		Wiring:          wiring,
		Command:         command,
		WorkDir:         s.WorkDir,
		ResolvedSecrets: resolved,
		Stdout:          stdout,
		Stderr:          stderr,
	}
	s.audit("harness.start", "allow", actor, map[string]any{
		"command": command,
		"secrets": len(resolved),
	})

	proc, err := s.launcher().Start(ctx, env)
	if err != nil {
		s.audit("harness.start", "error", actor, map[string]any{"error": err.Error()})
		return -1, err
	}

	code, werr := proc.Wait()
	s.audit("harness.stop", "observed", actor, map[string]any{
		"exit_code": code,
	})
	return code, werr
}

func (s *Supervisor) launcher() Launcher {
	if s.Launcher != nil {
		return s.Launcher
	}
	return ProcessLauncher{}
}

func (s *Supervisor) audit(action, decision, actor string, details map[string]any) {
	if s.Logger == nil {
		return
	}
	_ = s.Logger.Log(action, nil, decision, actor, details)
}

// clearSecrets drops resolved secret values from the map so they are no longer
// referenced once the agent exits. Go strings are immutable, so the backing
// bytes cannot be wiped in place; the guarantee here is that values are never
// persisted to disk and are released for garbage collection promptly. A future
// hardening pass can hold values as []byte for in-place zeroing.
func clearSecrets(m map[string]string) {
	for k := range m {
		delete(m, k)
	}
}
