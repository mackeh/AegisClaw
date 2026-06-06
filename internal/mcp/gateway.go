package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/mackeh/AegisClaw/internal/audit"
	"github.com/mackeh/AegisClaw/internal/guardrails"
	"github.com/mackeh/AegisClaw/internal/policy"
	"github.com/mackeh/AegisClaw/internal/scope"
)

// Gateway is an inline MCP proxy. It sits between an agent's MCP client and a
// real downstream MCP server, applying AegisClaw's enforcement to every tool
// call: scope→policy decision, persistent approval, argument and response
// guardrail scanning, tool-description pinning (tool-poisoning defense), rate
// limiting, and hash-chained audit. Calls that pass are forwarded to the
// downstream; calls that fail are blocked before they ever reach it.
//
// The gateway runs non-interactively — its stdin/stdout is the agent's JSON-RPC
// channel — so a RequireApproval policy decision is resolved against persisted
// "always" grants only; absent a grant, the call is denied by default. Operators
// grant approvals out-of-band (CLI/dashboard).
type Gateway struct {
	Downstream Downstream
	Policy     *policy.Engine
	Guard      *guardrails.Engine
	Logger     *audit.Logger
	Pins       *PinStore

	// ScopeMap maps a tool name to a capability scope string (e.g.
	// "files.write:/etc"). Unmapped tools default to a high-risk scope so the
	// policy must explicitly allow them.
	ScopeMap map[string]string
	// Approved reports whether a scope has a persisted "always" grant. Defaults
	// to always-false (deny-by-default) if nil.
	Approved func(scopeStr string) bool

	limiter     *rateLimiter
	quarantined map[string]bool
	mu          sync.Mutex
}

// NewGateway creates a gateway in front of the given downstream with safe
// defaults: a fresh guardrails engine, the default rate limit, an in-memory pin
// store, and deny-by-default approval.
func NewGateway(down Downstream) *Gateway {
	return &Gateway{
		Downstream:  down,
		Guard:       guardrails.NewEngine(),
		Pins:        NewMemoryPinStore(),
		limiter:     newRateLimiter(defaultMCPRateLimitPerMin, time.Minute),
		quarantined: make(map[string]bool),
		Approved:    func(string) bool { return false },
	}
}

// SetRateLimit overrides the per-minute tool-call limit (<=0 disables it).
func (g *Gateway) SetRateLimit(perMinute int) {
	g.limiter = newRateLimiter(perMinute, time.Minute)
}

// Run serves the agent's MCP session on stdin/stdout until EOF.
func (g *Gateway) Run(ctx context.Context) error {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			g.writeResponse(response{JSONRPC: "2.0", Error: &rpcError{Code: -32700, Message: "Parse error"}})
			continue
		}
		g.writeResponse(g.handleRequest(ctx, req))
	}
	return scanner.Err()
}

func (g *Gateway) handleRequest(ctx context.Context, req request) response {
	switch req.Method {
	case "initialize":
		raw, err := g.Downstream.Initialize(ctx, req.Params)
		if err != nil {
			return response{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32603, Message: err.Error()}}
		}
		return response{JSONRPC: "2.0", ID: req.ID, Result: raw}
	case "tools/list":
		return g.handleListTools(ctx, req)
	case "tools/call":
		return g.handleToolCall(ctx, req)
	default:
		return response{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32601, Message: fmt.Sprintf("Method not found: %s", req.Method)}}
	}
}

// handleListTools fetches the downstream tools, pins new ones (trust-on-first-
// use), and quarantines any whose description/schema changed since they were
// pinned — annotating them so the agent sees the warning.
func (g *Gateway) handleListTools(ctx context.Context, req request) response {
	tools, err := g.Downstream.ListTools(ctx)
	if err != nil {
		return response{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32603, Message: err.Error()}}
	}

	g.mu.Lock()
	for i := range tools {
		h := toolHash(tools[i])
		trusted, known := g.Pins.Get(tools[i].Name)
		switch {
		case !known:
			g.Pins.Set(tools[i].Name, h)
			delete(g.quarantined, tools[i].Name)
		case trusted != h:
			g.quarantined[tools[i].Name] = true
			tools[i].Description = "⚠️ [AegisClaw: tool description changed since first approval — calls blocked until re-approved] " + tools[i].Description
			g.audit("mcp.tool_pin", "quarantine", tools[i].Name, map[string]any{"reason": "description or schema changed"})
		default:
			delete(g.quarantined, tools[i].Name)
		}
	}
	g.mu.Unlock()
	_ = g.Pins.Save()

	return response{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{"tools": tools}}
}

func (g *Gateway) handleToolCall(ctx context.Context, req request) response {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return response{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32602, Message: "Invalid params"}}
	}
	if params.Name == "" {
		return response{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32602, Message: "Missing tool name"}}
	}

	// Rate limit.
	if g.limiter != nil && !g.limiter.allow(time.Now()) {
		g.audit("mcp.tool_call", "rate_limited", params.Name, nil)
		return response{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: rpcRateLimited, Message: "Rate limit exceeded: too many tool calls"}}
	}

	// Tool-poisoning quarantine.
	g.mu.Lock()
	quarantined := g.quarantined[params.Name]
	g.mu.Unlock()
	if quarantined {
		g.audit("mcp.tool_call", "deny", params.Name, map[string]any{"reason": "tool description changed; re-approval required"})
		return g.blocked(req.ID, "Tool description changed since it was approved; re-approval required (tool-poisoning defense).")
	}

	// Policy decision on the tool's scope.
	sc := g.scopeForTool(params.Name)
	if g.Policy == nil {
		g.audit("mcp.tool_call", "deny", params.Name, map[string]any{"reason": "no policy loaded"})
		return g.blocked(req.ID, "No policy loaded; denying tool call.")
	}
	decision, _, perr := g.Policy.EvaluateRequest(ctx, scope.ScopeRequest{
		RequestedBy: "mcp-gateway",
		Reason:      "tool call: " + params.Name,
		Scopes:      []scope.Scope{sc},
	})
	if perr != nil {
		g.audit("mcp.tool_call", "deny", params.Name, map[string]any{"reason": "policy error", "error": perr.Error()})
		return g.blocked(req.ID, "Policy evaluation failed; denying tool call.")
	}
	switch decision {
	case policy.Deny:
		g.audit("mcp.tool_call", "deny", params.Name, map[string]any{"scope": sc.String()})
		return g.blocked(req.ID, fmt.Sprintf("Policy denied tool %q (scope %s).", params.Name, sc.String()))
	case policy.RequireApproval:
		if g.Approved == nil || !g.Approved(sc.String()) {
			g.audit("mcp.tool_call", "require_approval", params.Name, map[string]any{"scope": sc.String()})
			return g.blocked(req.ID, fmt.Sprintf("Tool %q requires approval for scope %s. Grant it out-of-band, then retry.", params.Name, sc.String()))
		}
	}

	// Argument inspection: block credential exfiltration / injection smuggled
	// into the call arguments.
	if res := g.Guard.CheckData("mcp-args:"+params.Name, string(params.Arguments)); !res.Allowed {
		g.audit("mcp.tool_call", "deny", params.Name, map[string]any{"reason": "argument guardrail", "violations": violationRules(res.Violations)})
		return g.blocked(req.ID, "Tool call arguments blocked by guardrails (possible injection or secret exfiltration).")
	}

	// Forward to the downstream.
	raw, err := g.Downstream.CallTool(ctx, params.Name, params.Arguments)
	if err != nil {
		g.audit("mcp.tool_call", "error", params.Name, map[string]any{"error": err.Error()})
		return g.toolError(req.ID, fmt.Sprintf("Downstream error: %v", err))
	}

	// Response inspection: poisoned tool output must not re-enter the agent's
	// context.
	if res := g.Guard.CheckData("mcp-tool:"+params.Name, string(raw)); !res.Allowed {
		g.audit("mcp.tool_call", "deny", params.Name, map[string]any{"reason": "response guardrail", "violations": violationRules(res.Violations)})
		return g.blocked(req.ID, "Tool response blocked by guardrails (possible indirect prompt injection in tool output).")
	}

	g.audit("mcp.tool_call", "allow", params.Name, map[string]any{"scope": sc.String()})
	return response{JSONRPC: "2.0", ID: req.ID, Result: raw}
}

// scopeForTool maps a tool name to a capability scope. Unmapped tools get a
// high-risk scope so the policy must explicitly allow them.
func (g *Gateway) scopeForTool(name string) scope.Scope {
	if g.ScopeMap != nil {
		if s, ok := g.ScopeMap[name]; ok {
			parsed, err := scope.Parse(s)
			if err == nil {
				return parsed
			}
		}
	}
	return scope.Scope{Name: "mcp.tool", Resource: name, RiskLevel: scope.RiskHigh}
}

// blocked returns a non-error JSON-RPC result flagged as an MCP tool error, so
// the agent receives an explanatory message rather than a transport failure.
func (g *Gateway) blocked(id json.RawMessage, reason string) response {
	return g.toolError(id, "⛔ AegisClaw blocked this call: "+reason)
}

func (g *Gateway) toolError(id json.RawMessage, text string) response {
	return response{
		JSONRPC: "2.0",
		ID:      id,
		Result: map[string]any{
			"content": []map[string]any{{"type": "text", "text": text}},
			"isError": true,
		},
	}
}

func (g *Gateway) audit(action, decision, tool string, detail map[string]any) {
	if g.Logger == nil || tool == "" {
		return
	}
	if detail == nil {
		detail = map[string]any{}
	}
	_ = g.Logger.Log(action, nil, decision, tool, detail)
}

func (g *Gateway) writeResponse(resp response) {
	data, _ := json.Marshal(resp)
	fmt.Fprintf(os.Stdout, "%s\n", data)
}

func violationRules(vs []guardrails.Violation) []string {
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		out = append(out, string(v.Severity)+":"+v.Rule)
	}
	return out
}
