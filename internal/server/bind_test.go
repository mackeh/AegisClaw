package server

import "testing"

func TestIsLoopbackHost(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"127.0.0.1", true},
		{"localhost", true},
		{"LOCALHOST", true},
		{"::1", true},
		{"[::1]", true},
		{"127.0.0.5", true},
		{"", false},
		{"0.0.0.0", false},
		{"::", false},
		{"192.168.1.10", false},
		{"10.0.0.1", false},
		{"example.com", false},
	}
	for _, tt := range tests {
		if got := isLoopbackHost(tt.host); got != tt.want {
			t.Errorf("isLoopbackHost(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

func TestValidateBindAddress(t *testing.T) {
	tests := []struct {
		name           string
		host           string
		authConfigured bool
		insecure       bool
		wantErr        bool
	}{
		{"loopback always ok", "127.0.0.1", false, false, false},
		{"localhost always ok", "localhost", false, false, false},
		{"non-loopback without auth refused", "0.0.0.0", false, false, true},
		{"empty host (wildcard) refused", "", false, false, true},
		{"lan ip without auth refused", "192.168.1.10", false, false, true},
		{"non-loopback with auth allowed", "0.0.0.0", true, false, false},
		{"non-loopback with insecure allowed", "0.0.0.0", false, true, false},
		{"loopback ignores auth/insecure", "::1", false, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateBindAddress(tt.host, tt.authConfigured, tt.insecure)
			if tt.wantErr && err == nil {
				t.Errorf("expected error for host %q (auth=%v insecure=%v)", tt.host, tt.authConfigured, tt.insecure)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error for host %q: %v", tt.host, err)
			}
		})
	}
}
