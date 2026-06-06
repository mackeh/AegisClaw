// Package llmproxy is the model plane of the AegisClaw harness: an
// OpenAI/Anthropic-compatible reverse proxy that sits between an agent and its
// LLM provider. It scans prompts and responses with the guardrails engine,
// scrubs secrets from responses, enforces per-session token/cost/request
// budgets, detects runaway self-prompting loops, and records every call to the
// tamper-evident audit log — without the agent or the provider changing.
package llmproxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/mackeh/AegisClaw/internal/audit"
	"github.com/mackeh/AegisClaw/internal/guardrails"
	"github.com/mackeh/AegisClaw/internal/security/redactor"
)

const maxBodyBytes = 16 << 20 // 16MB cap on request/response bodies

// Proxy is the LLM reverse proxy.
type Proxy struct {
	// Upstream is the provider base URL (scheme://host), e.g.
	// "https://api.openai.com". The incoming request path is appended to it.
	Upstream string
	// Mode controls guardrail enforcement: "block", "warn", or "off".
	Mode string
	// Guard, Redactor, Logger, and Budget are the enforcement collaborators.
	Guard    *guardrails.Engine
	Redactor *redactor.Redactor
	Logger   *audit.Logger
	Budget   *Budget

	client *http.Client
	loop   *loopGuard
	server *http.Server
	port   int
}

// Options configures a Proxy.
type Options struct {
	Mode          string
	Secrets       []string // values scrubbed from responses
	Logger        *audit.Logger
	Budget        *Budget
	LoopThreshold int           // repeated identical requests that trips the loop guard (0 = off)
	LoopWindow    time.Duration // window for loop detection (default 60s)
}

// New creates a proxy forwarding to upstream with the given options.
func New(upstream string, opts Options) *Proxy {
	mode := opts.Mode
	if mode == "" {
		mode = "warn"
	}
	window := opts.LoopWindow
	if window == 0 {
		window = 60 * time.Second
	}
	return &Proxy{
		Upstream: strings.TrimRight(upstream, "/"),
		Mode:     mode,
		Guard:    guardrails.NewEngine(),
		Redactor: redactor.New(opts.Secrets...),
		Logger:   opts.Logger,
		Budget:   opts.Budget,
		client:   &http.Client{Timeout: 5 * time.Minute},
		loop:     newLoopGuard(opts.LoopThreshold, window),
	}
}

// Start binds the proxy to a loopback port and serves in the background,
// returning its base URL (e.g. "http://127.0.0.1:54321").
func (p *Proxy) Start() (string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	p.port = listener.Addr().(*net.TCPAddr).Port
	p.server = &http.Server{Handler: p}
	go p.server.Serve(listener)
	return fmt.Sprintf("http://127.0.0.1:%d", p.port), nil
}

// Stop shuts the proxy down.
func (p *Proxy) Stop() error {
	if p.server != nil {
		return p.server.Close()
	}
	return nil
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		p.writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}
	_ = r.Body.Close()

	model := extractModel(body)

	// Budget pre-check.
	if err := p.Budget.Check(); err != nil {
		p.audit("llm.request", "deny", model, map[string]any{"reason": "budget", "detail": err.Error()})
		p.writeError(w, http.StatusTooManyRequests, "AegisClaw budget exceeded: "+err.Error())
		return
	}

	// Loop guard.
	if _, tripped := p.loop.record(body, time.Now()); tripped {
		p.audit("llm.request", "deny", model, map[string]any{"reason": "loop detected"})
		p.writeError(w, http.StatusTooManyRequests, "AegisClaw blocked a runaway agent loop (repeated identical request)")
		return
	}

	// Input guardrails.
	prompt := extractPrompt(body)
	if p.Mode != "off" {
		if res := p.Guard.CheckInput(prompt); !res.Allowed {
			if p.Mode == "block" {
				p.audit("llm.request", "deny", model, map[string]any{"reason": "input guardrail", "violations": ruleNames(res.Violations)})
				p.writeError(w, http.StatusForbidden, "AegisClaw blocked the prompt (guardrail violation)")
				return
			}
			p.audit("llm.request", "warn", model, map[string]any{"reason": "input guardrail", "violations": ruleNames(res.Violations)})
		}
	}

	p.Budget.AddRequest()

	// Forward to the upstream provider.
	resp, err := p.forward(r, body)
	if err != nil {
		p.audit("llm.request", "error", model, map[string]any{"error": err.Error()})
		p.writeError(w, http.StatusBadGateway, "upstream error: "+err.Error())
		return
	}
	defer resp.Body.Close()

	// Streaming responses are passed through with secret redaction but without
	// response-body guardrail/usage parsing (documented limitation).
	if strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
		p.streamThrough(w, resp, model, prompt)
		return
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		p.writeError(w, http.StatusBadGateway, "failed to read upstream response")
		return
	}

	// Output guardrails on the assistant text.
	outText := extractResponseText(respBody)
	if p.Mode == "block" {
		if res := p.Guard.CheckOutput(outText); !res.Allowed {
			p.audit("llm.response", "deny", model, map[string]any{"reason": "output guardrail", "violations": ruleNames(res.Violations)})
			p.writeError(w, http.StatusForbidden, "AegisClaw blocked the model response (guardrail violation)")
			return
		}
	} else if p.Mode == "warn" {
		if res := p.Guard.CheckOutput(outText); !res.Allowed {
			p.audit("llm.response", "warn", model, map[string]any{"violations": ruleNames(res.Violations)})
		}
	}

	// Scrub any known secrets from the response.
	redacted := []byte(p.Redactor.Redact(string(respBody)))

	// Account usage and cost.
	u := extractUsage(respBody)
	if u.InputTokens == 0 && u.OutputTokens == 0 {
		u.InputTokens = estimateTokens(prompt)
		u.OutputTokens = estimateTokens(outText)
	}
	cost := priceFor(model).cost(u.InputTokens, u.OutputTokens)
	p.Budget.AddUsage(u.InputTokens, u.OutputTokens, cost)
	p.audit("llm.request", "allow", model, map[string]any{
		"input_tokens":  u.InputTokens,
		"output_tokens": u.OutputTokens,
		"cost_usd":      cost,
	})

	// Relay the (possibly redacted) response.
	copyHeaders(w.Header(), resp.Header)
	w.Header().Del("Content-Length")
	w.Header().Del("Content-Encoding")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(redacted)))
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(redacted)
}

// forward builds and sends the upstream request, preserving the path, query,
// method, and headers (including the agent's auth header). It requests an
// uncompressed response so the body can be inspected and redacted.
func (p *Proxy) forward(r *http.Request, body []byte) (*http.Response, error) {
	target := p.Upstream + r.URL.Path
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	out, err := http.NewRequestWithContext(r.Context(), r.Method, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	copyHeaders(out.Header, r.Header)
	out.Header.Del("Accept-Encoding")
	out.Header.Set("Accept-Encoding", "identity")
	out.Host = ""
	return p.client.Do(out)
}

func (p *Proxy) streamThrough(w http.ResponseWriter, resp *http.Response, model, prompt string) {
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	rw := redactor.NewRedactingWriter(w, p.Redactor)
	_, _ = io.Copy(rw, resp.Body)

	// Usage is estimated for streamed responses.
	in := estimateTokens(prompt)
	cost := priceFor(model).cost(in, 0)
	p.Budget.AddUsage(in, 0, cost)
	p.audit("llm.request", "allow", model, map[string]any{"input_tokens": in, "streamed": true, "cost_usd": cost})
}

func (p *Proxy) audit(action, decision, model string, detail map[string]any) {
	if p.Logger == nil {
		return
	}
	if detail == nil {
		detail = map[string]any{}
	}
	if model != "" {
		detail["model"] = model
	}
	_ = p.Logger.Log(action, nil, decision, "llm-proxy", detail)
}

func (p *Proxy) writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{"message": msg, "type": "aegisclaw_blocked"},
	})
}

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		if strings.EqualFold(k, "Host") {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

func ruleNames(vs []guardrails.Violation) []string {
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		out = append(out, string(v.Severity)+":"+v.Rule)
	}
	return out
}
