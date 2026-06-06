package sandbox

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/mackeh/AegisClaw/internal/proxy"
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
	if err := e.ensureImage(ctx, cfg.Image); err != nil {
		return nil, err
	}

	// Dynamic Network Configuration
	var egressProxy *proxy.EgressProxy
	proxyEnv := []string{}

	if cfg.Network { // If network is requested, enable filtering if domains are specified
		// Start egress proxy on host, listening on 127.0.0.1
		if len(cfg.AllowedDomains) > 0 {
			fmt.Printf("🌐 Enabling egress filtering for domains: %v\n", cfg.AllowedDomains)
			egressProxy = proxy.NewEgressProxy(cfg.AllowedDomains, cfg.AuditLogger)
			_, err := egressProxy.Start() // Proxy binds to 127.0.0.1
			if err != nil {
				return nil, fmt.Errorf("failed to start egress proxy: %w", err)
			}
			defer egressProxy.Stop()

			containerProxyURL := fmt.Sprintf("http://host.docker.internal:%d", egressProxy.Port)
			proxyEnv = []string{
				"http_proxy=" + containerProxyURL,
				"https_proxy=" + containerProxyURL,
				"HTTP_PROXY=" + containerProxyURL,
				"HTTPS_PROXY=" + containerProxyURL,
				"NO_PROXY=127.0.0.1,localhost", // Ensure no bypass for local traffic
			}
		}
	}

	// 2. Build hardened container + host config (shared with Start).
	config, hostConfig := hardenedConfigs(cfg, proxyEnv)

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
	select {
	case err := <-errCh:
		return nil, fmt.Errorf("error waiting for container: %w", err)
	case status := <-statusCh:
		_ = e.cli.ContainerRemove(context.Background(), containerID, container.RemoveOptions{})

		return &Result{
			ExitCode: int(status.StatusCode),
			Stdout:   stdoutReader,
			Stderr:   stderrReader,
		}, nil
	case <-ctx.Done():
		_ = e.cli.ContainerKill(ctx, containerID, "SIGKILL")
		return nil, ctx.Err()
	}
}

// ensureImage pulls the image if it is not already present locally.
func (e *DockerExecutor) ensureImage(ctx context.Context, img string) error {
	if _, _, err := e.cli.ImageInspectWithRaw(ctx, img); err == nil {
		return nil
	} else if !client.IsErrNotFound(err) {
		return fmt.Errorf("failed to inspect image: %w", err)
	}

	fmt.Printf("📥 Pulling image %s...\n", img)
	reader, err := e.cli.ImagePull(ctx, img, image.PullOptions{})
	if err != nil {
		return fmt.Errorf("failed to pull image: %w", err)
	}
	defer reader.Close()
	_, _ = io.Copy(io.Discard, reader)
	return nil
}

// hardenedConfigs builds the security-hardened container and host configuration
// shared by Run (one-shot skills) and Start (detached agents). extraEnv is
// appended to the caller's environment, e.g. egress proxy variables.
func hardenedConfigs(cfg Config, extraEnv []string) (*container.Config, *container.HostConfig) {
	hostConfig := &container.HostConfig{
		Runtime:        cfg.Runtime,
		CapDrop:        []string{"ALL"},               // Drop ALL capabilities
		SecurityOpt:    []string{"no-new-privileges"}, // No privilege escalation
		ReadonlyRootfs: true,                          // Read-only root filesystem
		Resources: container.Resources{
			Memory:     512 * 1024 * 1024, // 512MB RAM limit
			MemorySwap: 512 * 1024 * 1024, // No swap
			NanoCPUs:   1000000000,        // 1 CPU
			PidsLimit:  &[]int64{100}[0],  // Limit processes
		},
		ExtraHosts: []string{"host.docker.internal:host-gateway"}, // Reach host proxy
	}

	// Apply Seccomp profile if provided (read content for local-daemon compatibility).
	if cfg.SeccompPath != "" {
		if absPath, err := filepath.Abs(cfg.SeccompPath); err == nil {
			if profileData, err := os.ReadFile(absPath); err == nil {
				hostConfig.SecurityOpt = append(hostConfig.SecurityOpt, fmt.Sprintf("seccomp=%s", string(profileData)))
			}
		}
	}

	var mounts []mount.Mount
	for _, m := range cfg.Mounts {
		mounts = append(mounts, mount.Mount{
			Type:     mount.TypeBind,
			Source:   m.Source,
			Target:   m.Target,
			ReadOnly: m.ReadOnly,
		})
	}
	// Always provide a writable tmpfs for /tmp since the rootfs is read-only.
	mounts = append(mounts, mount.Mount{Type: mount.TypeTmpfs, Target: "/tmp"})
	hostConfig.Mounts = mounts

	if cfg.Network {
		hostConfig.NetworkMode = "bridge"
	} else {
		hostConfig.NetworkMode = "none" // Default-deny network
	}

	config := &container.Config{
		Image:        cfg.Image,
		Cmd:          cfg.Command,
		Env:          append(cfg.Env, extraEnv...),
		WorkingDir:   cfg.WorkDir,
		User:         "1000:1000", // Non-root user
		AttachStdout: true,
		AttachStderr: true,
		Tty:          false,
		Labels:       map[string]string{"managed_by": "aegisclaw"},
	}
	return config, hostConfig
}

// Process is a running, detached sandboxed container managed by AegisClaw.
type Process struct {
	cli         *client.Client
	containerID string
	exitCh      chan procExit
	done        chan struct{}
}

type procExit struct {
	code int
	err  error
}

// Start creates and starts a hardened container running cfg.Command, streams
// its stdout/stderr to the provided writers, and returns a handle without
// waiting for exit. It is the entry point the harness uses to run a long-lived
// agent process inside the sandbox.
//
// Unlike Run, Start does not manage an egress proxy: callers that need egress
// filtering inject proxy environment variables via cfg.Env and set cfg.Network
// to true. Cancelling ctx force-stops the container.
func (e *DockerExecutor) Start(ctx context.Context, cfg Config, stdout, stderr io.Writer) (*Process, error) {
	if err := e.ensureImage(ctx, cfg.Image); err != nil {
		return nil, err
	}

	config, hostConfig := hardenedConfigs(cfg, nil)
	resp, err := e.cli.ContainerCreate(ctx, config, hostConfig, &network.NetworkingConfig{}, nil, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create container: %w", err)
	}
	id := resp.ID

	if err := e.cli.ContainerStart(ctx, id, container.StartOptions{}); err != nil {
		_ = e.cli.ContainerRemove(context.Background(), id, container.RemoveOptions{Force: true})
		return nil, fmt.Errorf("failed to start container: %w", err)
	}

	logs, err := e.cli.ContainerLogs(ctx, id, container.LogsOptions{ShowStdout: true, ShowStderr: true, Follow: true})
	if err != nil {
		_ = e.cli.ContainerRemove(context.Background(), id, container.RemoveOptions{Force: true})
		return nil, fmt.Errorf("failed to attach logs: %w", err)
	}
	go func() {
		defer logs.Close()
		if stdout == nil {
			stdout = io.Discard
		}
		if stderr == nil {
			stderr = io.Discard
		}
		_, _ = stdcopy.StdCopy(stdout, stderr, logs)
	}()

	p := &Process{cli: e.cli, containerID: id, exitCh: make(chan procExit, 1), done: make(chan struct{})}

	go func() {
		statusCh, errCh := e.cli.ContainerWait(context.Background(), id, container.WaitConditionNotRunning)
		select {
		case werr := <-errCh:
			p.exitCh <- procExit{code: -1, err: werr}
		case status := <-statusCh:
			p.exitCh <- procExit{code: int(status.StatusCode)}
		}
		close(p.done)
		_ = e.cli.ContainerRemove(context.Background(), id, container.RemoveOptions{Force: true})
	}()

	// Tie ctx cancellation to container termination.
	go func() {
		select {
		case <-ctx.Done():
			_ = p.Stop()
		case <-p.done:
		}
	}()

	return p, nil
}

// Wait blocks until the container exits and returns its exit code. A non-zero
// exit code is not an error; err is non-nil only for unexpected failures.
func (p *Process) Wait() (int, error) {
	r := <-p.exitCh
	return r.code, r.err
}

// Stop force-stops the container.
func (p *Process) Stop() error {
	return p.cli.ContainerKill(context.Background(), p.containerID, "SIGKILL")
}

// ContainerID returns the underlying container ID.
func (p *Process) ContainerID() string { return p.containerID }

// KillAll force-stops and removes all containers managed by AegisClaw
func (e *DockerExecutor) KillAll(ctx context.Context) error {
	filters := filters.NewArgs()
	filters.Add("label", "managed_by=aegisclaw")

	containers, err := e.cli.ContainerList(ctx, container.ListOptions{All: true, Filters: filters})
	if err != nil {
		return fmt.Errorf("failed to list containers: %w", err)
	}

	for _, c := range containers {
		fmt.Printf("🛑 Killing container %s (%s)...\n", c.ID[:12], c.Image)
		// Force remove (kills if running)
		if err := e.cli.ContainerRemove(ctx, c.ID, container.RemoveOptions{Force: true}); err != nil {
			fmt.Printf("⚠️ Failed to remove container %s: %v\n", c.ID[:12], err)
		}
	}
	return nil
}

// Cleanup is a no-op for now as we remove containers after run
func (e *DockerExecutor) Cleanup(ctx context.Context) error {
	return nil
}

// getBridgeIP attempts to find the IP of the host on the default docker0 bridge
// This is a fallback/helper, for temporary networks we use the network's gateway IP.
func getBridgeIP() string {
	// Try docker0 interface first
	iface, err := net.InterfaceByName("docker0")
	if err == nil {
		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
					if ipnet.IP.To4() != nil {
						return ipnet.IP.String()
					}
				}
			}
		}
	}

	// Fallback to a common default
	return "172.17.0.1"
}

// generateRandomString creates a random hex string for unique identifiers
func generateRandomString(length int) string {
	b := make([]byte, (length+1)/2) // Each byte is 2 hex chars
	_, err := rand.Read(b)
	if err != nil {
		// Fallback for systems without enough entropy, though rare
		return fmt.Sprintf("%x", time.Now().UnixNano())[:length]
	}
	return hex.EncodeToString(b)[:length]
}
