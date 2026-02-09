package proxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/mackeh/AegisClaw/internal/audit"
)

// EgressProxy is a simple filtering proxy
type EgressProxy struct {
	AllowedDomains []string
	Port           int
	Logger         *audit.Logger
	server         *http.Server
}

func NewEgressProxy(allowed []string, logger *audit.Logger) *EgressProxy {
	return &EgressProxy{
		AllowedDomains: allowed,
		Logger:         logger,
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
	if !p.isAllowed(r.Host) {
		fmt.Printf("🚫 Blocked egress request to: %s\n", r.Host)
		http.Error(w, "Egress to this domain is blocked by AegisClaw policy", http.StatusForbidden)
		return
	}

	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}

	// Standard HTTP Proxy with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
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

	for k, v := range resp.Header {
		for _, vv := range v {
			w.Header().Add(k, vv)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (p *EgressProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		fmt.Printf("❌ Proxy CONNECT to %s failed: %v\n", r.Host, err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
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
