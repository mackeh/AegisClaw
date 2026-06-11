package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/mackeh/AegisClaw/internal/audit"
	"github.com/mackeh/AegisClaw/internal/guardrails"
)

// dlpMaxBody bounds how much of a plaintext request body the proxy will buffer
// to scan for secret exfiltration.
const dlpMaxBody = 4 << 20 // 4MB

// scanMaxBody bounds how much of a plaintext HTTP response the proxy buffers to
// scan for indirect prompt injection before relaying it.
const scanMaxBody = 4 << 20 // 4MB

// metadataIPs are cloud instance-metadata endpoints. Reaching them is almost
// never legitimate for an agent and is a classic credential-theft path
// (e.g. AWS/GCP/Azure 169.254.169.254, Alibaba 100.100.100.200), so they are
// blocked by default even when private-network egress is otherwise allowed.
var metadataIPs = []string{"169.254.169.254", "100.100.100.200", "fd00:ec2::254"}

// EgressProxy is a filtering forward proxy. Beyond a domain allowlist it
// enforces SSRF protection (no loopback/private/link-local/metadata
// destinations, validated at dial time to defeat DNS rebinding) and optional
// outbound DLP (blocks plaintext requests carrying known secret values).
type EgressProxy struct {
	AllowedDomains []string
	Port           int
	Logger         *audit.Logger

	// BlockPrivateIPs blocks destinations that resolve to loopback, private,
	// link-local, or unspecified addresses. Default true.
	BlockPrivateIPs bool
	// BlockMetadata blocks cloud instance-metadata endpoints. Default true; it
	// stays in effect even if BlockPrivateIPs is disabled.
	BlockMetadata bool

	// Guard, when set with GuardMode "warn" or "block", scans the bodies of
	// plaintext HTTP responses the agent fetches for indirect prompt injection.
	// HTTPS (CONNECT) responses are encrypted tunnels and cannot be inspected
	// here — the MCP gateway and LLM proxy cover the tool and model planes.
	Guard     *guardrails.Engine
	GuardMode string // "off" (default), "warn", or "block"

	secrets []string                            // known secret values for outbound DLP
	resolve func(host string) ([]net.IP, error) // injectable for tests
	server  *http.Server
}

func NewEgressProxy(allowed []string, logger *audit.Logger) *EgressProxy {
	return &EgressProxy{
		AllowedDomains:  allowed,
		Logger:          logger,
		BlockPrivateIPs: true,
		BlockMetadata:   true,
		resolve:         net.LookupIP,
	}
}

// AddSecret registers a secret value the proxy will block from leaving in a
// plaintext request. Short values are ignored to avoid false positives.
func (p *EgressProxy) AddSecret(s string) {
	if len(s) > 4 {
		p.secrets = append(p.secrets, s)
	}
}

func (p *EgressProxy) isAllowed(host string) bool {
	// Clean host (remove port)
	h := host
	if idx := strings.Index(host, ":"); idx != -1 {
		h = host[:idx]
	}

	allowed := false
	match := ""

	if len(p.AllowedDomains) == 0 {
		allowed = true // Default allow if no domains specified
	} else {
		for _, a := range p.AllowedDomains {
			if h == a || strings.HasSuffix(h, "."+a) {
				allowed = true
				match = a
				break
			}
		}
	}

	if allowed {
		if match != "" {
			fmt.Printf("✅ Allowed egress to: %s (matched %s)\n", h, match)
		} else {
			fmt.Printf("✅ Allowed egress to: %s (default allow)\n", h)
		}
	} else {
		fmt.Printf("🚫 Denied egress to: %s\n", h)
	}

	if p.Logger != nil {
		decision := "deny"
		if allowed {
			decision = "allow"
		}
		_ = p.Logger.Log("network.egress", nil, decision, "proxy", map[string]any{
			"host":    h,
			"matched": match,
		})
	}

	return allowed
}

func (p *EgressProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := hostnameOnly(r.Host)

	// SSRF guard: reject internal/metadata destinations before anything else.
	if blocked, reason := p.destBlocked(host); blocked {
		p.auditDeny(host, reason)
		http.Error(w, "Egress blocked by AegisClaw (SSRF protection): "+reason, http.StatusForbidden)
		return
	}

	if !p.isAllowed(r.Host) {
		fmt.Printf("🚫 Blocked egress request to: %s\n", r.Host)
		http.Error(w, "Egress to this domain is blocked by AegisClaw policy", http.StatusForbidden)
		return
	}

	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}

	// Outbound DLP on plaintext requests: block known secrets from leaving.
	if blocked, reason := p.dlpRequest(r); blocked {
		p.auditDeny(host, reason)
		http.Error(w, "Egress blocked by AegisClaw (data-loss prevention): "+reason, http.StatusForbidden)
		return
	}

	// Standard HTTP Proxy with timeout and SSRF-safe dialing.
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{DialContext: p.safeDial},
	}
	r.RequestURI = ""
	resp, err := client.Do(r)
	if err != nil {
		fmt.Printf("❌ Proxy HTTP request failed to %s: %v\n", r.URL.Host, err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("✅ Proxy received response from %s with status: %d\n", r.URL.Host, resp.StatusCode)

	// Scan fetched plaintext content for indirect prompt injection before it
	// flows back to the agent.
	if p.scanningEnabled() && isScannableResponse(resp) {
		p.scanRelay(w, resp, host)
		return
	}

	for k, v := range resp.Header {
		for _, vv := range v {
			w.Header().Add(k, vv)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (p *EgressProxy) scanningEnabled() bool {
	return p.Guard != nil && p.GuardMode != "" && p.GuardMode != "off"
}

// scanRelay buffers the response prefix, scans it for indirect prompt
// injection, and relays it. In "block" mode a violation replaces the body with
// a 502 so the poisoned content never reaches the agent; in "warn" mode it is
// audited and passed through.
func (p *EgressProxy) scanRelay(w http.ResponseWriter, resp *http.Response, host string) {
	prefix, _ := io.ReadAll(io.LimitReader(resp.Body, scanMaxBody))

	if res := p.Guard.CheckData("egress:"+host, string(prefix)); !res.Allowed {
		if p.GuardMode == "block" {
			p.auditDeny(host, "indirect prompt injection in fetched response: "+violationSummary(res.Violations))
			http.Error(w, "Response blocked by AegisClaw (indirect prompt injection in fetched content)", http.StatusBadGateway)
			return
		}
		fmt.Printf("⚠️  Guardrail violation in response from %s: %s\n", host, violationSummary(res.Violations))
		if p.Logger != nil {
			_ = p.Logger.Log("network.egress.response", nil, "warn", "proxy", map[string]any{
				"host": host, "violations": violationSummary(res.Violations),
			})
		}
	}

	for k, v := range resp.Header {
		for _, vv := range v {
			w.Header().Add(k, vv)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(prefix)
	_, _ = io.Copy(w, resp.Body) // relay anything beyond the scanned prefix
}

func (p *EgressProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	// Dial through the SSRF-safe dialer so the IP is validated at connect time.
	destConn, err := p.safeDial(r.Context(), "tcp", r.Host)
	if err != nil {
		fmt.Printf("❌ Proxy CONNECT to %s failed: %v\n", r.Host, err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		destConn.Close()
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		destConn.Close()
		return
	}

	go func() {
		defer destConn.Close()
		defer clientConn.Close()
		io.Copy(destConn, clientConn)
	}()
	go func() {
		defer destConn.Close()
		defer clientConn.Close()
		io.Copy(clientConn, destConn)
	}()
}

// safeDial resolves the target, blocks it if any resolved IP is a forbidden
// destination, and dials only a validated IP — closing the DNS-rebinding gap
// between an allowlist check and the actual connection.
func (p *EgressProxy) safeDial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host, port = addr, ""
	}

	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else if ips, err = p.resolveHost(host); err != nil {
		return nil, err
	}

	var target net.IP
	for _, ip := range ips {
		if blocked, reason := p.ipBlocked(ip); blocked {
			return nil, fmt.Errorf("destination %s blocked: %s", host, reason)
		}
		if target == nil {
			target = ip
		}
	}
	if target == nil {
		return nil, fmt.Errorf("could not resolve %s", host)
	}

	d := net.Dialer{Timeout: 10 * time.Second}
	dialAddr := target.String()
	if port != "" {
		dialAddr = net.JoinHostPort(target.String(), port)
	}
	return d.DialContext(ctx, network, dialAddr)
}

// destBlocked reports whether a destination host should be rejected up front
// (a fast, clear deny before forwarding). safeDial is the authoritative check.
func (p *EgressProxy) destBlocked(host string) (bool, string) {
	host = strings.TrimSpace(host)
	if host == "" {
		return false, ""
	}
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		resolved, err := p.resolveHost(host)
		if err != nil {
			return false, "" // let it fail downstream rather than block on DNS error
		}
		ips = resolved
	}
	for _, ip := range ips {
		if blocked, reason := p.ipBlocked(ip); blocked {
			return true, reason
		}
	}
	return false, ""
}

// ipBlocked classifies a destination IP against the SSRF policy.
func (p *EgressProxy) ipBlocked(ip net.IP) (bool, string) {
	if p.BlockMetadata && isMetadataIP(ip) {
		return true, "cloud metadata endpoint (" + ip.String() + ")"
	}
	if !p.BlockPrivateIPs {
		return false, ""
	}
	switch {
	case ip.IsLoopback():
		return true, "loopback address"
	case ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast():
		return true, "link-local address"
	case ip.IsPrivate():
		return true, "private network address"
	case ip.IsUnspecified():
		return true, "unspecified address"
	}
	return false, ""
}

func (p *EgressProxy) resolveHost(host string) ([]net.IP, error) {
	if p.resolve != nil {
		return p.resolve(host)
	}
	return net.LookupIP(host)
}

// dlpRequest blocks a plaintext request that carries a known secret in its URL
// or body. HTTPS (CONNECT) bodies are encrypted and cannot be inspected here —
// the LLM-proxy redactor covers that plane.
func (p *EgressProxy) dlpRequest(r *http.Request) (bool, string) {
	if len(p.secrets) == 0 {
		return false, ""
	}
	if containsAny(r.URL.String(), p.secrets) {
		return true, "known secret present in request URL"
	}
	if r.Body != nil && r.ContentLength >= 0 && r.ContentLength <= dlpMaxBody {
		body, err := io.ReadAll(io.LimitReader(r.Body, dlpMaxBody))
		_ = r.Body.Close()
		if err == nil {
			if containsAny(string(body), p.secrets) {
				return true, "known secret present in request body"
			}
			r.Body = io.NopCloser(bytes.NewReader(body)) // restore for forwarding
		}
	}
	return false, ""
}

func (p *EgressProxy) auditDeny(host, reason string) {
	fmt.Printf("🚫 Blocked egress to %s: %s\n", host, reason)
	if p.Logger != nil {
		_ = p.Logger.Log("network.egress", nil, "deny", "proxy", map[string]any{
			"host": host, "reason": reason,
		})
	}
}

// Start starts the proxy listening on 127.0.0.1:0
func (p *EgressProxy) Start() (string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	p.Port = listener.Addr().(*net.TCPAddr).Port
	p.server = &http.Server{Handler: p}

	go p.server.Serve(listener)

	return fmt.Sprintf("http://127.0.0.1:%d", p.Port), nil
}

func (p *EgressProxy) Stop() error {
	if p.server != nil {
		return p.server.Close()
	}
	return nil
}

func hostnameOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

func isMetadataIP(ip net.IP) bool {
	for _, m := range metadataIPs {
		if parsed := net.ParseIP(m); parsed != nil && parsed.Equal(ip) {
			return true
		}
	}
	return false
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if sub != "" && strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// isScannableResponse reports whether a response body is text-like enough to be
// worth scanning for prompt injection (skips images, archives, binaries).
func isScannableResponse(resp *http.Response) bool {
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if ct == "" {
		return true
	}
	for _, t := range []string{"text/", "html", "json", "xml", "javascript", "application/x-yaml", "+json", "+xml"} {
		if strings.Contains(ct, t) {
			return true
		}
	}
	return false
}

func violationSummary(vs []guardrails.Violation) string {
	parts := make([]string, 0, len(vs))
	for _, v := range vs {
		parts = append(parts, string(v.Severity)+":"+v.Rule)
	}
	return strings.Join(parts, ", ")
}
