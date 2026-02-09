package proxy

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/mackeh/AegisClaw/internal/audit"
)

func TestProxyFiltering(t *testing.T) {
	// Setup temporary audit log
	tmpDir, err := os.MkdirTemp("", "proxy-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	auditPath := filepath.Join(tmpDir, "audit.log")
	logger, err := audit.NewLogger(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()

	allowed := []string{"google.com", "example.org"}
	p := NewEgressProxy(allowed, logger)

	tests := []struct {
		host    string
		allowed bool
	}{
		{"google.com", true},
		{"sub.google.com", true},
		{"example.org", true},
		{"bing.com", false},
		{"malicious.com", false},
	}

	for _, tt := range tests {
		got := p.isAllowed(tt.host)
		if got != tt.allowed {
			t.Errorf("isAllowed(%q) = %v, want %v", tt.host, got, tt.allowed)
		}
	}

	// Verify ServeHTTP blocking
	req := httptest.NewRequest("GET", "http://bing.com", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("ServeHTTP(bing.com) code = %d, want %d", w.Code, http.StatusForbidden)
	}

	// Verify Audit Log
	entries, err := audit.ReadAll(auditPath)
	if err != nil {
		t.Fatal(err)
	}

	// We made 5 calls to isAllowed and 1 to ServeHTTP (which internally calls isAllowed)
	// Some calls were true, some were false.
	if len(entries) < 5 {
		t.Errorf("Audit log has %d entries, want at least 5", len(entries))
	}

	foundBlocked := false
	for _, entry := range entries {
		if entry.Action == "network.egress" && entry.Decision == "deny" {
			foundBlocked = true
			break
		}
	}

	if !foundBlocked {
		t.Error("Did not find any 'deny' entries in audit log")
	}
}
