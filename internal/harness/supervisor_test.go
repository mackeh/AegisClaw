package harness

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/mackeh/AegisClaw/internal/audit"
	"github.com/mackeh/AegisClaw/internal/secrets"
)

// TestSupervisorRun is an end-to-end Phase-1 test: it launches a real
// subprocess through the supervisor and verifies that (a) the egress proxy is
// wired into the agent's environment, (b) a scoped secret is resolved and
// injected, (c) the exit code propagates, and (d) the secret value never
// appears in the audit log.
func TestSupervisorRun(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}

	dir := t.TempDir()

	// Seed an encrypted secret store.
	mgr := secrets.NewManager(dir)
	if _, err := mgr.Init(); err != nil {
		t.Fatalf("secrets init: %v", err)
	}
	const secretVal = "topsecret-value-xyz"
	if err := mgr.Set("MY_API", secretVal); err != nil {
		t.Fatalf("secrets set: %v", err)
	}

	logPath := filepath.Join(dir, "audit.log")
	logger, err := audit.NewLogger(logPath)
	if err != nil {
		t.Fatalf("audit logger: %v", err)
	}
	defer logger.Close()

	adapter := &stubAdapter{
		name: "test",
		wiring: Wiring{
			Secrets: []ScopedSecret{
				{EnvVar: "AGENT_KEY", SecretName: "MY_API", Scope: "secrets.access:MY_API"},
			},
		},
		ingress: []IngressSource{{Name: "test-chan", Kind: "chat-channel"}},
		prepare: func(args []string) ([]string, error) {
			return []string{"sh", "-c", "echo proxy=$HTTP_PROXY; echo key=$AGENT_KEY; exit 7"}, nil
		},
	}

	sup := &Supervisor{
		ConfigDir:      dir,
		Logger:         logger,
		Secrets:        mgr,
		AllowedDomains: []string{"example.com"},
	}

	var stdout, stderr bytes.Buffer
	code, err := sup.Run(context.Background(), adapter, []string{"ignored"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("supervisor run: %v", err)
	}
	if code != 7 {
		t.Fatalf("expected exit code 7, got %d", code)
	}

	out := stdout.String()
	if !strings.Contains(out, "proxy=http://127.0.0.1:") {
		t.Errorf("egress proxy not wired into agent env; stdout=%q", out)
	}
	if !strings.Contains(out, "key="+secretVal) {
		t.Errorf("scoped secret not injected; stdout=%q", out)
	}

	// Redaction guarantee: the secret value must never hit the audit log.
	entries, err := audit.ReadAll(logPath)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	var actions []string
	for _, e := range entries {
		actions = append(actions, e.Action)
		raw, _ := json.Marshal(e)
		if strings.Contains(string(raw), secretVal) {
			t.Fatalf("secret value leaked into audit entry: %s", raw)
		}
	}

	for _, want := range []string{"harness.plane.network", "harness.secret.inject", "harness.ingress.register", "harness.start", "harness.stop"} {
		if !containsStr(actions, want) {
			t.Errorf("audit missing action %q; got %v", want, actions)
		}
	}
}

func TestSupervisorMissingSecretIsNonFatal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	dir := t.TempDir()
	mgr := secrets.NewManager(dir)
	if _, err := mgr.Init(); err != nil {
		t.Fatalf("secrets init: %v", err)
	}

	adapter := &stubAdapter{
		name:   "test",
		wiring: Wiring{Secrets: []ScopedSecret{{EnvVar: "K", SecretName: "ABSENT"}}},
		prepare: func([]string) ([]string, error) {
			return []string{"sh", "-c", "exit 0"}, nil
		},
	}
	sup := &Supervisor{ConfigDir: dir, Secrets: mgr}

	code, err := sup.Run(context.Background(), adapter, []string{"x"}, &bytes.Buffer{}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("run with missing secret should not error: %v", err)
	}
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
}

// sandboxRequirerStub is a stubAdapter that also requires the sandbox.
type sandboxRequirerStub struct{ *stubAdapter }

func (sandboxRequirerStub) RequiresSandbox() bool { return true }

func TestSupervisorMergesAdapterEgressDomains(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	logger, err := audit.NewLogger(logPath)
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	defer logger.Close()

	adapter := &stubAdapter{
		name:   "test",
		egress: []string{"api.telegram.org", "example.com"},
		prepare: func([]string) ([]string, error) {
			return []string{"sh", "-c", "exit 0"}, nil
		},
	}
	sup := &Supervisor{
		Logger:         logger,
		AllowedDomains: []string{"example.com"}, // overlaps with adapter
	}
	if _, err := sup.Run(context.Background(), adapter, []string{"x"}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatalf("run: %v", err)
	}

	entries, _ := audit.ReadAll(logPath)
	var allowlist []any
	for _, e := range entries {
		if e.Action == "harness.plane.network" {
			allowlist, _ = e.Details["allowlist"].([]any)
		}
	}
	// Union of {example.com} and {api.telegram.org, example.com} = 2 entries.
	if len(allowlist) != 2 {
		t.Fatalf("expected merged+deduped allowlist of 2, got %v", allowlist)
	}
}

func TestSupervisorWarnsWhenSandboxRequiredOnHost(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	logger, _ := audit.NewLogger(logPath)
	defer logger.Close()

	adapter := sandboxRequirerStub{&stubAdapter{
		name:    "codeexec",
		prepare: func([]string) ([]string, error) { return []string{"sh", "-c", "exit 0"}, nil },
	}}
	sup := &Supervisor{Logger: logger} // no Image => host launch

	if _, err := sup.Run(context.Background(), adapter, []string{"x"}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatalf("run: %v", err)
	}
	entries, _ := audit.ReadAll(logPath)
	var warned bool
	for _, e := range entries {
		if e.Action == "harness.sandbox.recommended" {
			warned = true
		}
	}
	if !warned {
		t.Fatal("expected harness.sandbox.recommended audit event when a code-executing agent runs on host")
	}
}

func containsStr(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}
