// Package sandboxlauncher implements harness.Launcher by running the agent
// inside a hardened AegisClaw sandbox container (the host plane). It is kept in
// a subpackage so the heavy Docker dependency stays out of the core harness
// package; the CLI selects it when an image is supplied.
package sandboxlauncher

import (
	"context"
	"fmt"
	"net/url"

	"github.com/mackeh/AegisClaw/internal/harness"
	"github.com/mackeh/AegisClaw/internal/sandbox"
)

// Launcher runs the agent inside a hardened sandbox container.
type Launcher struct {
	Runtime string // sandbox runtime name: docker (default), gvisor, kata, firecracker
}

// New returns a sandbox-backed launcher using the given runtime ("" = docker).
func New(runtime string) *Launcher { return &Launcher{Runtime: runtime} }

// Start implements harness.Launcher.
func (l *Launcher) Start(ctx context.Context, env harness.HarnessEnv) (harness.AgentProcess, error) {
	if env.Image == "" {
		return nil, fmt.Errorf("sandbox launcher requires an image (set --image)")
	}
	runtimeFlag, err := sandbox.ResolveRuntime(l.Runtime)
	if err != nil {
		return nil, err
	}
	exec, err := sandbox.NewDockerExecutor()
	if err != nil {
		return nil, err
	}

	cfg := sandbox.Config{
		Image:   env.Image,
		Command: env.Command,
		Env:     containerEnv(env),
		WorkDir: env.WorkDir,
		Network: true, // the agent needs egress, filtered through the proxy
		Runtime: runtimeFlag,
	}

	proc, err := exec.Start(ctx, cfg, env.Stdout, env.Stderr)
	if err != nil {
		return nil, err
	}
	return proc, nil
}

// containerEnv builds the container environment from the wiring, rewriting the
// loopback egress-proxy address to host.docker.internal so the container can
// reach the proxy on the host. The host environment is deliberately NOT
// inherited — the sandboxed agent gets only what the harness grants it.
func containerEnv(env harness.HarnessEnv) []string {
	var out []string
	if p := containerProxyURL(env.Wiring.HTTPProxy); p != "" {
		out = append(out,
			"HTTP_PROXY="+p, "http_proxy="+p,
			"HTTPS_PROXY="+p, "https_proxy="+p,
			"NO_PROXY=127.0.0.1,localhost", "no_proxy=127.0.0.1,localhost",
		)
	}
	for k, v := range env.Wiring.Env {
		// Rewrite any loopback URLs (e.g. the LLM-proxy base URL) so the
		// container reaches the host service via the Docker gateway.
		out = append(out, k+"="+containerProxyURL(v))
	}
	for k, v := range env.ResolvedSecrets {
		out = append(out, k+"="+v)
	}
	return out
}

// containerProxyURL rewrites a host-loopback proxy URL to one reachable from
// inside the container via the Docker host gateway.
func containerProxyURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	switch u.Hostname() {
	case "127.0.0.1", "localhost", "::1":
		if port := u.Port(); port != "" {
			u.Host = "host.docker.internal:" + port
		} else {
			u.Host = "host.docker.internal"
		}
	}
	return u.String()
}
