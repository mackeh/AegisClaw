//go:build linux

package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

const (
	bpfEventSyscall    = 1
	bpfEventNetConnect = 2
	bpfEventFileOpen   = 3
)

// bpfEvent matches the struct event in monitor.c
type bpfEvent struct {
	Type uint32
	PID  uint32
	TID  uint32
	Comm [16]byte
	Data [64]byte // max size of the union
}

// loadProbes attaches eBPF programs to kernel tracepoints on Linux.
// Requires CAP_BPF or root privileges.
func (m *Monitor) loadProbes(ctx context.Context) error {
	// Check for BPF support
	if _, err := os.Stat("/sys/fs/bpf"); os.IsNotExist(err) {
		return fmt.Errorf("eBPF not supported: /sys/fs/bpf not mounted")
	}

	// Check privileges
	if os.Geteuid() != 0 {
		return fmt.Errorf("eBPF monitoring requires root privileges (CAP_BPF)")
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		return fmt.Errorf("loading objects: %w", err)
	}

	// Attach probes
	var links []link.Link

	// 1. Syscall tracer
	tpSys, err := link.Tracepoint("raw_syscalls", "sys_enter", objs.TraceSysEnter, nil)
	if err != nil {
		objs.Close()
		return fmt.Errorf("opening sys_enter tracepoint: %w", err)
	}
	links = append(links, tpSys)

	// 2. Openat tracer
	tpOpen, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TraceOpenat, nil)
	if err == nil {
		links = append(links, tpOpen)
	}

	// 3. TCP Connect tracer
	kpNet, err := link.Kprobe("tcp_v4_connect", objs.TraceTcpV4Connect, nil)
	if err == nil {
		links = append(links, kpNet)
	}

	// Open a ringbuf reader
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		for _, l := range links {
			l.Close()
		}
		objs.Close()
		return fmt.Errorf("opening ringbuf reader: %w", err)
	}

	// Process events in a background goroutine
	go func() {
		defer rd.Close()
		for _, l := range links {
			defer l.Close()
		}
		defer objs.Close()

		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				continue
			}

			var event bpfEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				continue
			}

			evt := Event{
				PID:       event.PID,
				TID:       event.TID,
				Comm:      string(bytes.TrimRight(event.Comm[:], "\x00")),
				Timestamp: time.Now(),
			}

			switch event.Type {
			case bpfEventSyscall:
				syscallID := binary.LittleEndian.Uint64(event.Data[:8])
				evt.Type = EventSyscall
				evt.Syscall = fmt.Sprintf("syscall_%d", syscallID)
			case bpfEventFileOpen:
				evt.Type = EventFileOpen
				evt.FilePath = string(bytes.TrimRight(event.Data[:], "\x00"))
			case bpfEventNetConnect:
				evt.Type = EventNetConnect
				// In a real implementation we'd decode IP/Port from event.Data
			}

			m.Emit(evt)
		}
	}()

	return nil
}
