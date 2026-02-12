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

// bpfEvent matches the struct event in monitor.c
type bpfEvent struct {
	PID       uint32
	TID       uint32
	Comm      [16]byte
	SyscallID uint64
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

	// Attach the program to the raw_syscalls/sys_enter tracepoint.
	tp, err := link.Tracepoint("raw_syscalls", "sys_enter", objs.TraceSysEnter, nil)
	if err != nil {
		objs.Close()
		return fmt.Errorf("opening tracepoint: %w", err)
	}

	// Open a ringbuf reader from userspace side which receives events from the kernel-side map.
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		tp.Close()
		objs.Close()
		return fmt.Errorf("opening ringbuf reader: %w", err)
	}

	// Process events in a background goroutine
	go func() {
		defer rd.Close()
		defer tp.Close()
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

			// Emit the event to the monitor
			m.Emit(Event{
				Type:      EventSyscall,
				PID:       event.PID,
				TID:       event.TID,
				Comm:      string(bytes.TrimRight(event.Comm[:], "\x00")),
				Syscall:   fmt.Sprintf("syscall_%d", event.SyscallID),
				Timestamp: time.Now(),
			})
		}
	}()

	return nil
}
