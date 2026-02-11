// Package xray provides deep runtime inspection of running skill containers.
// It captures resource usage (CPU, memory, network), active processes, and
// container metadata for live monitoring and debugging.
package xray

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

// Snapshot represents a point-in-time inspection of a running container.
type Snapshot struct {
	ContainerID   string          `json:"container_id"`
	ContainerName string          `json:"container_name"`
	Image         string          `json:"image"`
	Status        string          `json:"status"`
	StartedAt     string          `json:"started_at"`
	Resources     ResourceStats   `json:"resources"`
	Processes     []ProcessInfo   `json:"processes,omitempty"`
	Network       []NetworkStats  `json:"network,omitempty"`
	Timestamp     string          `json:"timestamp"`
}

// ResourceStats holds CPU and memory usage data.
type ResourceStats struct {
	CPUPercent float64 `json:"cpu_percent"`
	MemoryMB   float64 `json:"memory_mb"`
	MemoryMax  float64 `json:"memory_max_mb"`
	MemoryPct  float64 `json:"memory_percent"`
	PIDs       uint64  `json:"pids"`
}

// ProcessInfo describes a single process running in the container.
type ProcessInfo struct {
	PID     string `json:"pid"`
	User    string `json:"user"`
	Command string `json:"command"`
}

// NetworkStats holds per-interface network I/O.
type NetworkStats struct {
	Interface string `json:"interface"`
	RxBytes   uint64 `json:"rx_bytes"`
	TxBytes   uint64 `json:"tx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	TxPackets uint64 `json:"tx_packets"`
}

// Inspector inspects running Docker containers.
type Inspector struct {
	cli *client.Client
}

// NewInspector creates an Inspector using the default Docker socket.
func NewInspector() (*Inspector, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("docker client: %w", err)
	}
	return &Inspector{cli: cli}, nil
}

// ListAegisClaw returns snapshots for all AegisClaw-managed containers.
func (i *Inspector) ListAegisClaw(ctx context.Context) ([]Snapshot, error) {
	containers, err := i.cli.ContainerList(ctx, container.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}

	var snapshots []Snapshot
	for _, c := range containers {
		// Filter to aegisclaw containers by label
		if _, ok := c.Labels["aegisclaw.skill"]; !ok {
			continue
		}
		snap, err := i.Inspect(ctx, c.ID)
		if err != nil {
			continue
		}
		snapshots = append(snapshots, *snap)
	}
	return snapshots, nil
}

// Inspect captures a full snapshot of a single container.
func (i *Inspector) Inspect(ctx context.Context, containerID string) (*Snapshot, error) {
	info, err := i.cli.ContainerInspect(ctx, containerID)
	if err != nil {
		return nil, fmt.Errorf("inspect: %w", err)
	}

	snap := &Snapshot{
		ContainerID:   containerID[:12],
		ContainerName: info.Name,
		Image:         info.Config.Image,
		Status:        info.State.Status,
		StartedAt:     info.State.StartedAt,
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
	}

	// Resource stats from container stats API
	stats, err := i.cli.ContainerStats(ctx, containerID, false)
	if err == nil {
		defer stats.Body.Close()
		var s container.StatsResponse
		if json.NewDecoder(stats.Body).Decode(&s) == nil {
			snap.Resources = calcResources(s)
			snap.Network = calcNetwork(s)
		}
	}

	// Process list
	top, err := i.cli.ContainerTop(ctx, containerID, []string{})
	if err == nil {
		snap.Processes = parseTop(top)
	}

	return snap, nil
}

func calcResources(s container.StatsResponse) ResourceStats {
	rs := ResourceStats{
		PIDs: s.PidsStats.Current,
	}

	// CPU percent calculation
	cpuDelta := float64(s.CPUStats.CPUUsage.TotalUsage - s.PreCPUStats.CPUUsage.TotalUsage)
	sysDelta := float64(s.CPUStats.SystemUsage - s.PreCPUStats.SystemUsage)
	if sysDelta > 0 && cpuDelta > 0 {
		rs.CPUPercent = (cpuDelta / sysDelta) * float64(len(s.CPUStats.CPUUsage.PercpuUsage)) * 100.0
	}

	// Memory
	rs.MemoryMB = float64(s.MemoryStats.Usage) / 1024 / 1024
	rs.MemoryMax = float64(s.MemoryStats.Limit) / 1024 / 1024
	if s.MemoryStats.Limit > 0 {
		rs.MemoryPct = float64(s.MemoryStats.Usage) / float64(s.MemoryStats.Limit) * 100.0
	}

	return rs
}

func calcNetwork(s container.StatsResponse) []NetworkStats {
	var nets []NetworkStats
	for name, n := range s.Networks {
		nets = append(nets, NetworkStats{
			Interface: name,
			RxBytes:   n.RxBytes,
			TxBytes:   n.TxBytes,
			RxPackets: n.RxPackets,
			TxPackets: n.TxPackets,
		})
	}
	return nets
}

func parseTop(top container.ContainerTopOKBody) []ProcessInfo {
	var procs []ProcessInfo
	// Find column indices
	pidIdx, userIdx, cmdIdx := -1, -1, -1
	for i, title := range top.Titles {
		switch title {
		case "PID":
			pidIdx = i
		case "USER", "UID":
			userIdx = i
		case "CMD", "COMMAND":
			cmdIdx = i
		}
	}

	for _, proc := range top.Processes {
		p := ProcessInfo{}
		if pidIdx >= 0 && pidIdx < len(proc) {
			p.PID = proc[pidIdx]
		}
		if userIdx >= 0 && userIdx < len(proc) {
			p.User = proc[userIdx]
		}
		if cmdIdx >= 0 && cmdIdx < len(proc) {
			p.Command = proc[cmdIdx]
		}
		procs = append(procs, p)
	}
	return procs
}
