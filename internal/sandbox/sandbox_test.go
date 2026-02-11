package sandbox

import (
	"testing"
)

func TestResolveRuntime(t *testing.T) {
	tests := []struct {
		input   string
		want    string
		wantErr bool
	}{
		{"", "", false},
		{"docker", "", false},
		{"gvisor", "runsc", false},
		{"runsc", "runsc", false},
		{"kata", "kata-runtime", false},
		{"kata-runtime", "kata-runtime", false},
		{"firecracker", "kata-fc", false},
		{"kata-fc", "kata-fc", false},
		{"unknown", "", true},
	}

	for _, tt := range tests {
		got, err := ResolveRuntime(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ResolveRuntime(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if got != tt.want {
			t.Errorf("ResolveRuntime(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
