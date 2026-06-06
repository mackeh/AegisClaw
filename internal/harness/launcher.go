package harness

import (
	"context"
	"fmt"
	"os"
	"os/exec"
)

// Launcher starts an agent process from a fully-resolved HarnessEnv. The
// abstraction is the seam between the network/secret wiring (which is
// launcher-independent) and *where* the agent actually runs.
//
// ProcessLauncher (below) runs the agent as a host subprocess with the wiring
// injected as environment variables — outbound traffic is filtered because the
// agent is pointed at the egress proxy via HTTP(S)_PROXY. A sandbox-backed
// launcher that runs the agent inside Docker/gVisor (the host plane) implements
// this same interface and is the next increment.
type Launcher interface {
	Start(ctx context.Context, env HarnessEnv) (AgentProcess, error)
}

// ProcessLauncher runs the agent as a host subprocess.
type ProcessLauncher struct{}

// Start launches the command in env.Command with the wiring applied.
func (ProcessLauncher) Start(ctx context.Context, env HarnessEnv) (AgentProcess, error) {
	if len(env.Command) == 0 {
		return nil, fmt.Errorf("no command to launch")
	}

	cmd := exec.CommandContext(ctx, env.Command[0], env.Command[1:]...)
	cmd.Dir = env.WorkDir
	cmd.Stdout = env.Stdout
	cmd.Stderr = env.Stderr
	cmd.Stdin = os.Stdin
	cmd.Env = buildEnv(env)

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start agent: %w", err)
	}
	return &processHandle{cmd: cmd}, nil
}

// buildEnv composes the child environment: the inherited environment, then the
// wiring overrides, then injected secrets. Later entries win for duplicate keys
// (standard os/exec semantics), so wiring and secrets override anything
// inherited from the parent.
func buildEnv(env HarnessEnv) []string {
	out := os.Environ()

	if p := env.Wiring.HTTPProxy; p != "" {
		out = append(out,
			"HTTP_PROXY="+p, "http_proxy="+p,
			"HTTPS_PROXY="+p, "https_proxy="+p,
			"NO_PROXY=127.0.0.1,localhost", "no_proxy=127.0.0.1,localhost",
		)
	}
	// LLMBaseURL / MCPEndpoint are populated in later phases; an adapter that
	// knows the provider-specific variable name carries it in Wiring.Env.

	for k, v := range env.Wiring.Env {
		out = append(out, k+"="+v)
	}
	for k, v := range env.ResolvedSecrets {
		out = append(out, k+"="+v)
	}
	return out
}

// processHandle adapts an *exec.Cmd to AgentProcess.
type processHandle struct {
	cmd *exec.Cmd
}

func (h *processHandle) Wait() (int, error) {
	err := h.cmd.Wait()
	if err == nil {
		return 0, nil
	}
	var ee *exec.ExitError
	if ok := asExitError(err, &ee); ok {
		return ee.ExitCode(), nil // non-zero exit is not a harness error
	}
	return -1, err
}

func (h *processHandle) Stop() error {
	if h.cmd.Process == nil {
		return nil
	}
	return h.cmd.Process.Kill()
}

// asExitError is a tiny errors.As wrapper kept separate so the import set stays
// obvious at call sites.
func asExitError(err error, target **exec.ExitError) bool {
	if ee, ok := err.(*exec.ExitError); ok {
		*target = ee
		return true
	}
	return false
}
