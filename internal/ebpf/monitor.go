// Package ebpf provides kernel-level runtime monitoring using eBPF probes.
// It traces syscalls, network flows, and file access for running skill containers
// with near-zero overhead compared to strace/seccomp audit.
//
// This package defines the monitoring interfaces and event types.
// Actual eBPF program loading requires a Linux kernel with BPF support.
package ebpf

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// EventType identifies the kind of eBPF event.
type EventType string

const (
	EventSyscall    EventType = "syscall"
	EventNetConnect EventType = "net_connect"
	EventNetBind    EventType = "net_bind"
	EventFileOpen   EventType = "file_open"
	EventFileWrite  EventType = "file_write"
	EventProcessExec EventType = "process_exec"
)

// Event represents a single kernel-level event captured by eBPF probes.
type Event struct {
	Type      EventType `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	PID       uint32    `json:"pid"`
	TID       uint32    `json:"tid"`
	Comm      string    `json:"comm"`       // process name
	ContainerID string  `json:"container_id,omitempty"`

	// Syscall fields
	Syscall string `json:"syscall,omitempty"`
	RetVal  int64  `json:"retval,omitempty"`

	// Network fields
	SrcAddr string `json:"src_addr,omitempty"`
	DstAddr string `json:"dst_addr,omitempty"`
	SrcPort uint16 `json:"src_port,omitempty"`
	DstPort uint16 `json:"dst_port,omitempty"`
	Proto   string `json:"proto,omitempty"` // tcp, udp

	// File fields
	FilePath string `json:"file_path,omitempty"`
	Flags    int32  `json:"flags,omitempty"`
}

// EventHandler processes captured eBPF events.
type EventHandler func(Event)

// ProbeConfig configures which eBPF probes to attach.
type ProbeConfig struct {
	TraceSyscalls bool     `json:"trace_syscalls"`
	TraceNetwork  bool     `json:"trace_network"`
	TraceFiles    bool     `json:"trace_files"`
	TraceProcess  bool     `json:"trace_process"`
	FilterPIDs    []uint32 `json:"filter_pids,omitempty"`    // only trace these PIDs
	FilterComm    []string `json:"filter_comm,omitempty"`    // only trace these process names
}

// Monitor manages eBPF probe lifecycle and event streaming.
type Monitor struct {
	mu       sync.RWMutex
	config   ProbeConfig
	handlers []EventHandler
	running  bool
	cancel   context.CancelFunc
	events   chan Event
	stats    MonitorStats
}

// MonitorStats tracks monitoring metrics.
type MonitorStats struct {
	EventsTotal   uint64        `json:"events_total"`
	EventsByType  map[EventType]uint64 `json:"events_by_type"`
	DroppedEvents uint64        `json:"dropped_events"`
	StartedAt     time.Time     `json:"started_at"`
	Uptime        time.Duration `json:"uptime"`
}

// NewMonitor creates a new eBPF monitor with the given probe configuration.
func NewMonitor(config ProbeConfig) *Monitor {
	return &Monitor{
		config:  config,
		events:  make(chan Event, 4096),
		stats: MonitorStats{
			EventsByType: make(map[EventType]uint64),
		},
	}
}

// OnEvent registers an event handler that will be called for each captured event.
func (m *Monitor) OnEvent(handler EventHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers = append(m.handlers, handler)
}

// Start begins eBPF monitoring. Returns an error if probes cannot be loaded.
// On non-Linux or unprivileged systems, returns ErrNotSupported.
func (m *Monitor) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return fmt.Errorf("monitor already running")
	}
	m.running = true
	m.stats.StartedAt = time.Now()
	ctx, m.cancel = context.WithCancel(ctx)
	m.mu.Unlock()

	// Start the event dispatch goroutine
	go m.dispatch(ctx)

	// Start the platform-specific probe loader
	return m.loadProbes(ctx)
}

// Stop halts eBPF monitoring and detaches all probes.
func (m *Monitor) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.running {
		return
	}
	m.running = false
	if m.cancel != nil {
		m.cancel()
	}
	close(m.events)
}

// IsRunning returns whether the monitor is actively tracing.
func (m *Monitor) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

// Stats returns current monitoring statistics.
func (m *Monitor) Stats() MonitorStats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s := m.stats
	if m.running {
		s.Uptime = time.Since(s.StartedAt)
	}
	return s
}

// Emit sends an event into the monitor's event channel.
// Used by probe callbacks. Non-blocking; drops events if buffer is full.
func (m *Monitor) Emit(evt Event) {
	select {
	case m.events <- evt:
		m.mu.Lock()
		m.stats.EventsTotal++
		m.stats.EventsByType[evt.Type]++
		m.mu.Unlock()
	default:
		m.mu.Lock()
		m.stats.DroppedEvents++
		m.mu.Unlock()
	}
}

func (m *Monitor) dispatch(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-m.events:
			if !ok {
				return
			}
			m.mu.RLock()
			for _, h := range m.handlers {
				h(evt)
			}
			m.mu.RUnlock()
		}
	}
}
