package sandbox

import (
	"context"
	"io"
)

// Result represents the outcome of a sandbox execution
type Result struct {
	ExitCode int
	Stdout   io.Reader
	Stderr   io.Reader
}

// Config represents the configuration for a sandbox
type Config struct {
	Image       string
	Command     []string
	Env         []string
	WorkDir     string
	Mounts         []Mount // Host path -> Container path
	Network        bool    // Allow network access?
	AllowedDomains []string // Specific domains to allow if Network is true
	SeccompPath    string  // Path to seccomp profile
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
