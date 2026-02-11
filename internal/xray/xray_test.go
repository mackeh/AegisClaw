package xray

import (
	"testing"

	"github.com/docker/docker/api/types/container"
)

func TestCalcResources(t *testing.T) {
	stats := container.StatsResponse{}
	stats.CPUStats.CPUUsage.TotalUsage = 200000000
	stats.PreCPUStats.CPUUsage.TotalUsage = 100000000
	stats.CPUStats.SystemUsage = 2000000000
	stats.PreCPUStats.SystemUsage = 1000000000
	stats.CPUStats.CPUUsage.PercpuUsage = []uint64{0, 0, 0, 0}
	stats.MemoryStats.Usage = 50 * 1024 * 1024
	stats.MemoryStats.Limit = 512 * 1024 * 1024
	stats.PidsStats.Current = 5

	rs := calcResources(stats)

	if rs.PIDs != 5 {
		t.Errorf("expected 5 PIDs, got %d", rs.PIDs)
	}

	// CPU: (100M/1000M) * 4 cores * 100 = 40%
	if rs.CPUPercent < 39.0 || rs.CPUPercent > 41.0 {
		t.Errorf("expected ~40%% CPU, got %.2f%%", rs.CPUPercent)
	}

	// Memory: 50MB
	if rs.MemoryMB < 49.0 || rs.MemoryMB > 51.0 {
		t.Errorf("expected ~50MB memory, got %.2f MB", rs.MemoryMB)
	}

	// Memory %: 50/512 * 100 ≈ 9.77%
	if rs.MemoryPct < 9.0 || rs.MemoryPct > 10.0 {
		t.Errorf("expected ~9.77%% memory, got %.2f%%", rs.MemoryPct)
	}
}

func TestCalcResources_ZeroDelta(t *testing.T) {
	stats := container.StatsResponse{}
	// Same values for CPU = zero delta
	stats.CPUStats.CPUUsage.TotalUsage = 100
	stats.PreCPUStats.CPUUsage.TotalUsage = 100

	rs := calcResources(stats)
	if rs.CPUPercent != 0 {
		t.Errorf("expected 0%% CPU for zero delta, got %.2f%%", rs.CPUPercent)
	}
}

func TestCalcNetwork(t *testing.T) {
	stats := container.StatsResponse{}
	stats.Networks = map[string]container.NetworkStats{
		"eth0": {RxBytes: 1000, TxBytes: 2000, RxPackets: 10, TxPackets: 20},
		"lo":   {RxBytes: 500, TxBytes: 500, RxPackets: 5, TxPackets: 5},
	}

	nets := calcNetwork(stats)
	if len(nets) != 2 {
		t.Errorf("expected 2 network entries, got %d", len(nets))
	}

	found := map[string]bool{}
	for _, n := range nets {
		found[n.Interface] = true
	}
	if !found["eth0"] || !found["lo"] {
		t.Error("expected eth0 and lo interfaces")
	}
}

func TestCalcNetwork_Empty(t *testing.T) {
	stats := container.StatsResponse{}
	nets := calcNetwork(stats)
	if len(nets) != 0 {
		t.Errorf("expected 0 network entries, got %d", len(nets))
	}
}

func TestParseTop(t *testing.T) {
	top := container.ContainerTopOKBody{
		Titles:    []string{"PID", "USER", "COMMAND"},
		Processes: [][]string{
			{"1", "root", "/bin/sh"},
			{"42", "app", "python main.py"},
		},
	}

	procs := parseTop(top)
	if len(procs) != 2 {
		t.Fatalf("expected 2 processes, got %d", len(procs))
	}

	if procs[0].PID != "1" || procs[0].User != "root" || procs[0].Command != "/bin/sh" {
		t.Errorf("unexpected first process: %+v", procs[0])
	}
	if procs[1].PID != "42" || procs[1].User != "app" || procs[1].Command != "python main.py" {
		t.Errorf("unexpected second process: %+v", procs[1])
	}
}

func TestParseTop_MissingColumns(t *testing.T) {
	top := container.ContainerTopOKBody{
		Titles:    []string{"UID", "PID"},
		Processes: [][]string{
			{"root", "1"},
		},
	}

	procs := parseTop(top)
	if len(procs) != 1 {
		t.Fatalf("expected 1 process, got %d", len(procs))
	}
	if procs[0].PID != "1" {
		t.Errorf("expected PID '1', got '%s'", procs[0].PID)
	}
	if procs[0].User != "root" {
		t.Errorf("expected user 'root', got '%s'", procs[0].User)
	}
}

func TestParseTop_Empty(t *testing.T) {
	top := container.ContainerTopOKBody{
		Titles:    []string{"PID", "USER", "CMD"},
		Processes: [][]string{},
	}

	procs := parseTop(top)
	if len(procs) != 0 {
		t.Errorf("expected 0 processes, got %d", len(procs))
	}
}
