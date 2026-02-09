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

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
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

	// Dynamic Network Configuration
	var networkID string
	var egressProxy *proxy.EgressProxy
	proxyEnv := []string{}

	if cfg.Network {
		// Create a temporary isolated bridge network
		networkName := fmt.Sprintf("aegisclaw-net-%s", generateRandomString(8))
		netResp, err := e.cli.NetworkCreate(ctx, networkName, types.NetworkCreate{
			Driver:     "bridge",
			Internal:   true, // Isolated network
			Attachable: false,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create isolated network: %w", err)
		}
		networkID = netResp.ID
		defer func() {
			err := e.cli.NetworkRemove(context.Background(), networkID)
			if err != nil {
				fmt.Printf("Error removing network %s: %v\n", networkName, err)
			}
		}()

		// Get the host's IP on this new network for proxy communication
		netResource, err := e.cli.NetworkInspect(ctx, networkID, types.NetworkInspectOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to inspect network %s: %w", networkName, err)
		}
		
		if len(netResource.IPAM.Config) == 0 || netResource.IPAM.Config[0].Gateway == "" {
			return nil, fmt.Errorf("could not find gateway IP for network %s", networkName)
		}
		hostIP := netResource.IPAM.Config[0].Gateway // The gateway IP is the host's IP on the bridge

		// Start egress proxy on host, listening on this specific IP
		if len(cfg.AllowedDomains) > 0 {
			fmt.Printf("🌐 Enabling egress filtering for domains: %v\n", cfg.AllowedDomains)
			egressProxy = proxy.NewEgressProxy(cfg.AllowedDomains)
			// Start proxy on the specific IP found for the Docker bridge
			_, err := egressProxy.StartOnIP(hostIP) 
			if err != nil {
				return nil, fmt.Errorf("failed to start egress proxy: %w", err)
			}
			defer egressProxy.Stop()

			containerProxyURL := fmt.Sprintf("http://%s:%d", hostIP, egressProxy.Port)
			proxyEnv = []string{
				"http_proxy=" + containerProxyURL,
				"https_proxy=" + containerProxyURL,
				"HTTP_PROXY=" + containerProxyURL,
				"HTTPS_PROXY=" + containerProxyURL,
				"NO_PROXY=127.0.0.1,localhost", // Ensure no bypass for local traffic
			}
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
	if cfg.Network {
		hostConfig.NetworkMode = container.NetworkMode(networkID) // Use the isolated network
	} else {
		hostConfig.NetworkMode = "none" // No network access by default
	}

	// 2. Create Container
	containerEnv := append(cfg.Env, proxyEnv...)
	config := &container.Config{
		Image:        cfg.Image,
		Cmd:          cfg.Command,
		Env:          containerEnv,
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