package proxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// EgressProxy is a simple filtering proxy
type EgressProxy struct {
	AllowedDomains []string
	Port           int
	server         *http.Server
}

func NewEgressProxy(allowed []string) *EgressProxy {
	return &EgressProxy{
		AllowedDomains: allowed,
	}
}

func (p *EgressProxy) isAllowed(host string) bool {
	if len(p.AllowedDomains) == 0 {
		return true // Default allow if no domains specified
	}

	// Clean host (remove port)
	h := host
	if idx := strings.Index(host, ":"); idx != -1 {
		h = host[:idx]
	}

	for _, allowed := range p.AllowedDomains {
		if h == allowed || strings.HasSuffix(h, "."+allowed) {
			fmt.Printf("✅ Allowed egress to: %s (matched %s)\n", h, allowed)
			return true
		}
	}
	fmt.Printf("🚫 Denied egress to: %s\n", h)
	return false
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
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

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

func (p *EgressProxy) Start() (string, error) {
	listener, err := net.Listen("tcp", "0.0.0.0:0")
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