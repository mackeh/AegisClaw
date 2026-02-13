//go:build linux && !amd64 && !386

package ebpf

import (
	"context"
	"fmt"
)

// loadProbes is a no-op on Linux architectures without generated eBPF objects.
func (m *Monitor) loadProbes(ctx context.Context) error {
	return fmt.Errorf("eBPF monitoring is not yet supported on this Linux architecture")
}
