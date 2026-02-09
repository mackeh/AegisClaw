package sandbox

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
)

// DockerExecutor implements Executor using Docker
type DockerExecutor struct {
	cli *client.Client
}

// NewDockerExecutor creates a new Docker sandbox executor
func NewDockerExecutor() (*DockerExecutor, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create docker client: %w", err)
	}
	return &DockerExecutor{cli: cli}, nil
}

// Run executes a command in a hardened Docker container
func (e *DockerExecutor) Run(ctx context.Context, cfg Config) (*Result, error) {
	// 1. Ensure image exists
	_, _, err := e.cli.ImageInspectWithRaw(ctx, cfg.Image)
	if err != nil {
		if client.IsErrNotFound(err) {
			fmt.Printf("📥 Pulling image %s...\n", cfg.Image)
			reader, err := e.cli.ImagePull(ctx, cfg.Image, image.PullOptions{})
			if err != nil {
				return nil, fmt.Errorf("failed to pull image: %w", err)
			}
			defer reader.Close()
			io.Copy(io.Discard, reader)
		} else {
			return nil, fmt.Errorf("failed to inspect image: %w", err)
		}
	}

	// 2. Configure HostConfig for security
	hostConfig := &container.HostConfig{
		// Drop ALL capabilities by default
		CapDrop: []string{"ALL"},
		
		// Prevent privilege escalation
		SecurityOpt: []string{"no-new-privileges"},
		
		// Read-only root filesystem
		ReadonlyRootfs: true,
		
		// Resources
		Resources: container.Resources{
			Memory:     512 * 1024 * 1024, // 512MB RAM limit
			MemorySwap: 512 * 1024 * 1024, // No swap
			NanoCPUs:   1000000000,        // 1 CPU
			PidsLimit:  &[]int64{100}[0],  // Limit processes
		},
	}

	// Apply Seccomp profile if provided
	if cfg.SeccompPath != "" {
		absPath, err := filepath.Abs(cfg.SeccompPath)
		if err == nil {
			// Docker expects the profile content, or "unconfined", or "default"
			// But for custom profiles file path is tricky with remote daemon.
			// For local daemon, we can read the file and pass it as json string.
			profileData, err := os.ReadFile(absPath)
			if err == nil {
				hostConfig.SecurityOpt = append(hostConfig.SecurityOpt, fmt.Sprintf("seccomp=%s", string(profileData)))
			}
		}
	}

	// Configure Mounts
	var mounts []mount.Mount
	for _, m := range cfg.Mounts {
		mounts = append(mounts, mount.Mount{
			Type:     mount.TypeBind,
			Source:   m.Source,
			Target:   m.Target,
			ReadOnly: m.ReadOnly,
		})
	}
	// Always mount a tmpfs for /tmp if filesystem is read-only
	mounts = append(mounts, mount.Mount{
		Type:   mount.TypeTmpfs,
		Target: "/tmp",
	})
	hostConfig.Mounts = mounts

	// Configure Network
	networkMode := "none"
	if cfg.Network {
		networkMode = "bridge" // Or specific user network
	}
	hostConfig.NetworkMode = container.NetworkMode(networkMode)

	// 2. Create Container
	config := &container.Config{
		Image:        cfg.Image,
		Cmd:          cfg.Command,
		Env:          cfg.Env,
		WorkingDir:   cfg.WorkDir,
		User:         "1000:1000", // Non-root user
		AttachStdout: true,
		AttachStderr: true,
		Tty:          false,
	}

	resp, err := e.cli.ContainerCreate(ctx, config, hostConfig, &network.NetworkingConfig{}, nil, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create container: %w", err)
	}

	containerID := resp.ID

	// 4. Start Container
	if err := e.cli.ContainerStart(ctx, containerID, container.StartOptions{}); err != nil {
		return nil, fmt.Errorf("failed to start container: %w", err)
	}

	// 4. Attach to logs
	out, err := e.cli.ContainerLogs(ctx, containerID, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get container logs: %w", err)
	}

	// Demultiplex stream
	stdoutReader, stdoutWriter := io.Pipe()
	stderrReader, stderrWriter := io.Pipe()

	go func() {
		defer out.Close()
		defer stdoutWriter.Close()
		defer stderrWriter.Close()
		stdcopy.StdCopy(stdoutWriter, stderrWriter, out)
	}()

	// 5. Wait for exit
	statusCh, errCh := e.cli.ContainerWait(ctx, containerID, container.WaitConditionNotRunning)
	
	// Create a result that will be populated when Wait returns
	// For async usage, we might want to return immediately. 
	// But for this sync implementation:
	select {
	case err := <-errCh:
		return nil, fmt.Errorf("error waiting for container: %w", err)
	case status := <-statusCh:
		// Cleanup immediately for this simple implementation
		// In prod, might want to keep for forensic if exit code != 0
		_ = e.cli.ContainerRemove(ctx, containerID, container.RemoveOptions{})
		
		return &Result{
			ExitCode: int(status.StatusCode),
			Stdout:   stdoutReader,
			Stderr:   stderrReader,
		}, nil
	case <-ctx.Done():
		// Kill container on context cancellation
		_ = e.cli.ContainerKill(ctx, containerID, "SIGKILL")
		return nil, ctx.Err()
	}
}

// Cleanup is a no-op for now as we remove containers after run
func (e *DockerExecutor) Cleanup(ctx context.Context) error {
	return nil
}
