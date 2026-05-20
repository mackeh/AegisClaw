package server

import (
	"fmt"
	"net"
	"strings"
)

// isLoopbackHost reports whether host refers only to the local machine.
// An empty host is treated as a wildcard bind (all interfaces), not loopback.
func isLoopbackHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return false
	}
	if h == "localhost" {
		return true
	}
	if ip := net.ParseIP(strings.Trim(h, "[]")); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// validateBindAddress guards against silently exposing the API server to the
// network — the failure mode behind unauthenticated-RCE incidents in other
// agents. Loopback binds are always allowed. A non-loopback bind is refused
// unless API-token authentication is configured, or the operator has
// explicitly accepted the risk with --insecure.
func validateBindAddress(host string, authConfigured, insecure bool) error {
	if isLoopbackHost(host) || authConfigured || insecure {
		return nil
	}
	shown := host
	if shown == "" {
		shown = "0.0.0.0 (all interfaces)"
	}
	return fmt.Errorf("refusing to bind the API server to non-loopback address %q without authentication: "+
		"configure API tokens in ~/.aegisclaw/auth.yaml, or pass --insecure to override (NOT recommended)", shown)
}
