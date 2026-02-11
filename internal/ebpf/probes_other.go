//go:build !linux

package ebpf

import (
	"context"
	"fmt"
)

// loadProbes is a no-op on non-Linux platforms.
func (m *Monitor) loadProbes(ctx context.Context) error {
	return fmt.Errorf("eBPF monitoring is only supported on Linux")
}
