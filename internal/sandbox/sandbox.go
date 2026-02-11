package sandbox

import (
	"context"
	"fmt"
	"io"

	"github.com/mackeh/AegisClaw/internal/audit"
)

// Runtime identifies a sandbox backend.
const (
	RuntimeDocker      = "docker"      // Default: Docker with runc
	RuntimeGVisor      = "gvisor"      // Docker with gVisor (runsc)
	RuntimeKata        = "kata"        // Docker with Kata Containers
	RuntimeFirecracker = "firecracker" // Docker with Firecracker (via kata-fc)
)

// Result represents the outcome of a sandbox execution
type Result struct {
	ExitCode int
	Stdout   io.Reader
	Stderr   io.Reader
}

// Config represents the configuration for a sandbox
type Config struct {
	Image          string
	Command        []string
	Env            []string
	WorkDir        string
	Mounts         []Mount  // Host path -> Container path
	Network        bool     // Allow network access?
	AllowedDomains []string // Specific domains to allow if Network is true
	AuditLogger    *audit.Logger
	SeccompPath    string // Path to seccomp profile
	Runtime        string // e.g. "runsc" (gVisor), "kata-runtime" (kata), "runc" (default)
}

// Mount represents a filesystem mount
type Mount struct {
	Source   string
	Target   string
	ReadOnly bool
}

// Executor defines the interface for sandboxed execution
type Executor interface {
	// Run executes a command in the sandbox and returns the result.
	// The caller is responsible for reading Stdout/Stderr.
	Run(ctx context.Context, cfg Config) (*Result, error)

	// Cleanup removes resources associated with the sandbox
	Cleanup(ctx context.Context) error
}

// NewExecutor creates the appropriate executor for the given runtime.
// All runtimes currently use Docker as the orchestrator, just with different
// OCI runtime binaries. The runtime string maps to:
//   - "docker" or ""      → Docker with default runc
//   - "gvisor"            → Docker with --runtime=runsc
//   - "kata"              → Docker with --runtime=kata-runtime
//   - "firecracker"       → Docker with --runtime=kata-fc
func NewExecutor(runtime string) (Executor, error) {
	exec, err := NewDockerExecutor()
	if err != nil {
		return nil, err
	}
	return exec, nil
}

// ResolveRuntime maps a user-facing runtime name to the Docker --runtime flag value.
func ResolveRuntime(name string) (string, error) {
	switch name {
	case "", RuntimeDocker:
		return "", nil // Docker default (runc)
	case RuntimeGVisor, "runsc":
		return "runsc", nil
	case RuntimeKata, "kata-runtime":
		return "kata-runtime", nil
	case RuntimeFirecracker, "kata-fc":
		return "kata-fc", nil
	default:
		return "", fmt.Errorf("unknown sandbox runtime: %s (supported: docker, gvisor, kata, firecracker)", name)
	}
}
