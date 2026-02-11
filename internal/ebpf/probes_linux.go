//go:build linux

package ebpf

import (
	"context"
	"fmt"
	"os"
)

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

	// TODO: Load compiled eBPF programs and attach to tracepoints
	// This is a foundation — actual BPF bytecode compilation requires
	// bpf2go or pre-compiled .o files.
	//
	// Planned tracepoints:
	//   - tracepoint/raw_syscalls/sys_enter (syscall tracing)
	//   - kprobe/tcp_connect (network connect)
	//   - kprobe/tcp_v4_connect (IPv4 connects)
	//   - tracepoint/syscalls/sys_enter_openat (file opens)
	//   - tracepoint/sched/sched_process_exec (process exec)

	return fmt.Errorf("eBPF probe loading not yet implemented — foundation only")
}
