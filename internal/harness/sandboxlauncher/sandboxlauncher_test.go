package sandboxlauncher

import (
	"context"
	"strings"
	"testing"

	"github.com/mackeh/AegisClaw/internal/harness"
)

func TestContainerProxyURL(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"", ""},
		{"http://127.0.0.1:8080", "http://host.docker.internal:8080"},
		{"http://localhost:9999", "http://host.docker.internal:9999"},
		{"http://example.com:3128", "http://example.com:3128"}, // external proxy untouched
	}
	for _, tt := range tests {
		if got := containerProxyURL(tt.in); got != tt.want {
			t.Errorf("containerProxyURL(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestContainerEnvRewritesProxyAndInjectsSecrets(t *testing.T) {
	env := harness.HarnessEnv{
		Wiring: harness.Wiring{
			HTTPProxy: "http://127.0.0.1:5000",
			Env:       map[string]string{"AGENT_MODE": "prod"},
		},
		ResolvedSecrets: map[string]string{"API_KEY": "v"},
	}
	got := strings.Join(containerEnv(env), "\n")

	for _, want := range []string{
		"HTTP_PROXY=http://host.docker.internal:5000",
		"https_proxy=http://host.docker.internal:5000",
		"AGENT_MODE=prod",
		"API_KEY=v",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("containerEnv missing %q; got:\n%s", want, got)
		}
	}
	// The host environment must not leak into the sandbox.
	if strings.Contains(got, "127.0.0.1:5000") {
		t.Errorf("loopback proxy address not rewritten for container")
	}
}

func TestStartRequiresImage(t *testing.T) {
	_, err := New("").Start(context.Background(), harness.HarnessEnv{Command: []string{"sh"}})
	if err == nil {
		t.Fatal("expected error when image is empty")
	}
}

func TestStartRejectsUnknownRuntime(t *testing.T) {
	_, err := New("bogus").Start(context.Background(), harness.HarnessEnv{Image: "alpine", Command: []string{"sh"}})
	if err == nil {
		t.Fatal("expected error for unknown runtime")
	}
}
