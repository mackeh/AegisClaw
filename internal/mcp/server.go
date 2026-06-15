// Package mcp implements a Model Context Protocol server for AegisClaw.
// It allows AI assistants like Claude Code to interact with AegisClaw
// via the stdio transport.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/mackeh/AegisClaw/internal/audit"
	"github.com/mackeh/AegisClaw/internal/compliance"
	"github.com/mackeh/AegisClaw/internal/config"
	"github.com/mackeh/AegisClaw/internal/lineage"
	"github.com/mackeh/AegisClaw/internal/posture"
	"github.com/mackeh/AegisClaw/internal/skill"
)

const (
	// defaultMCPRateLimitPerMin bounds tool calls per minute. It is generous
	// for an interactive AI assistant but stops runaway loops.
	defaultMCPRateLimitPerMin = 120
	// maxAuditQueryLimit caps how many audit entries a single query returns.
	maxAuditQueryLimit = 1000
	// rpcRateLimited is the JSON-RPC error code for a throttled request
	// (within the -32000..-32099 server-error range).
	rpcRateLimited = -32000
)

// JSON-RPC 2.0 types
type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Tool describes an MCP tool.
type Tool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema interface{} `json:"inputSchema"`
}

// Server implements the MCP stdio protocol.
type Server struct {
	tools   []Tool
	limiter *rateLimiter
	logger  *audit.Logger // tamper-evident log of tool calls; nil if unavailable
}

// NewServer creates an MCP server with AegisClaw tools.
func NewServer() *Server {
	return &Server{
		limiter: newRateLimiter(defaultMCPRateLimitPerMin, time.Minute),
		tools: []Tool{
			{
				Name:        "aegisclaw_list_skills",
				Description: "List all installed AegisClaw skills",
				InputSchema: map[string]interface{}{
					"type":       "object",
					"properties": map[string]interface{}{},
				},
			},
			{
				Name:        "aegisclaw_audit_query",
				Description: "Query AegisClaw audit log entries",
				InputSchema: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"limit": map[string]interface{}{
							"type":        "number",
							"description": "Maximum number of entries to return",
						},
					},
				},
			},
			{
				Name:        "aegisclaw_posture",
				Description: "Get the current AegisClaw security posture score",
				InputSchema: map[string]interface{}{
					"type":       "object",
					"properties": map[string]interface{}{},
				},
			},
			{
				Name:        "aegisclaw_verify_logs",
				Description: "Verify the integrity of the AegisClaw audit log hash chain",
				InputSchema: map[string]interface{}{
					"type":       "object",
					"properties": map[string]interface{}{},
				},
			},
			{
				Name:        "aegisclaw_compliance",
				Description: "Assess AegisClaw against the OWASP Top 10 for Agentic Applications (ASI01-ASI10). Returns per-control coverage, scores, and gaps.",
				InputSchema: map[string]interface{}{
					"type":       "object",
					"properties": map[string]interface{}{},
				},
			},
			{
				Name:        "aegisclaw_compliance_report",
				Description: "Generate a full compliance report combining OWASP ASI assessment, audit trail summary, and policy evaluation history",
				InputSchema: map[string]interface{}{
					"type":       "object",
					"properties": map[string]interface{}{},
				},
			},
			{
				Name:        "aegisclaw_lineage",
				Description: "Query data lineage records tracking inputs, outputs, secrets accessed, and API calls for skill executions",
				InputSchema: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"skill": map[string]interface{}{
							"type":        "string",
							"description": "Filter by skill name",
						},
						"execution_id": map[string]interface{}{
							"type":        "string",
							"description": "Filter by execution ID",
						},
						"limit": map[string]interface{}{
							"type":        "number",
							"description": "Maximum number of records to return",
						},
					},
				},
			},
		},
	}
}

// SetRateLimit overrides the per-minute tool-call limit. A value of zero or
// less disables rate limiting.
func (s *Server) SetRateLimit(perMinute int) {
	s.limiter = newRateLimiter(perMinute, time.Minute)
}

// openMCPAuditLogger opens a dedicated, hash-chained audit log for MCP tool
// calls. It is kept separate from the main audit.log so the two processes
// never interleave appends and corrupt each other's hash chain.
func openMCPAuditLogger() (*audit.Logger, error) {
	dir, err := config.DefaultConfigDir()
	if err != nil {
		return nil, err
	}
	auditDir := filepath.Join(dir, "audit")
	if err := os.MkdirAll(auditDir, 0o700); err != nil {
		return nil, err
	}
	return audit.NewLogger(filepath.Join(auditDir, "mcp.log"))
}

// logToolCall records an MCP tool invocation to the audit log, if available.
func (s *Server) logToolCall(tool, decision string, detail map[string]any) {
	if s.logger == nil || tool == "" {
		return
	}
	if detail == nil {
		detail = map[string]any{}
	}
	_ = s.logger.Log("mcp.tool_call", nil, decision, tool, detail)
}

// Run starts the MCP server on stdio, reading JSON-RPC requests and writing responses.
func (s *Server) Run(ctx context.Context) error {
	if s.logger == nil {
		if logger, err := openMCPAuditLogger(); err == nil {
			s.logger = logger
		}
	}

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1MB buffer

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			s.writeError(nil, -32700, "Parse error")
			continue
		}

		resp := s.handleRequest(ctx, req)
		s.writeResponse(resp)
	}

	return scanner.Err()
}

func (s *Server) handleRequest(ctx context.Context, req request) response {
	switch req.Method {
	case "initialize":
		return response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]interface{}{
				"protocolVersion": "2024-11-05",
				"capabilities": map[string]interface{}{
					"tools": map[string]interface{}{},
				},
				"serverInfo": map[string]interface{}{
					"name":    "aegisclaw",
					"version": "0.10.0",
				},
			},
		}

	case "tools/list":
		return response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]interface{}{
				"tools": s.tools,
			},
		}

	case "tools/call":
		return s.handleToolCall(ctx, req)

	default:
		return response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &rpcError{Code: -32601, Message: fmt.Sprintf("Method not found: %s", req.Method)},
		}
	}
}

func (s *Server) handleToolCall(ctx context.Context, req request) response {
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

	if s.limiter != nil && !s.limiter.allow(time.Now()) {
		s.logToolCall(params.Name, "rate_limited", nil)
		return response{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: rpcRateLimited, Message: "Rate limit exceeded: too many tool calls"}}
	}

	var result interface{}
	var err error

	switch params.Name {
	case "aegisclaw_list_skills":
		result, err = s.toolListSkills()
	case "aegisclaw_audit_query":
		result, err = s.toolAuditQuery(params.Arguments)
	case "aegisclaw_posture":
		result, err = s.toolPosture()
	case "aegisclaw_verify_logs":
		result, err = s.toolVerifyLogs()
	case "aegisclaw_compliance":
		result, err = s.toolCompliance()
	case "aegisclaw_compliance_report":
		result, err = s.toolComplianceReport()
	case "aegisclaw_lineage":
		result, err = s.toolLineage(params.Arguments)
	default:
		s.logToolCall(params.Name, "unknown_tool", nil)
		return response{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32602, Message: fmt.Sprintf("Unknown tool: %s", params.Name)}}
	}

	if err != nil {
		s.logToolCall(params.Name, "error", map[string]any{"error": err.Error()})
		return response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]interface{}{
				"content": []map[string]interface{}{
					{"type": "text", "text": fmt.Sprintf("Error: %v", err)},
				},
				"isError": true,
			},
		}
	}

	s.logToolCall(params.Name, "allow", nil)

	text, _ := json.MarshalIndent(result, "", "  ")
	return response{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"content": []map[string]interface{}{
				{"type": "text", "text": string(text)},
			},
		},
	}
}

func (s *Server) toolListSkills() (interface{}, error) {
	cfgDir, err := config.DefaultConfigDir()
	if err != nil {
		return nil, err
	}

	manifests, _ := skill.ListSkills(filepath.Join(cfgDir, "skills"))
	localManifests, _ := skill.ListSkills("skills")
	manifests = append(manifests, localManifests...)

	type skillInfo struct {
		Name        string   `json:"name"`
		Version     string   `json:"version"`
		Description string   `json:"description"`
		Scopes      []string `json:"scopes"`
		Commands    []string `json:"commands"`
	}

	var skills []skillInfo
	for _, m := range manifests {
		var cmds []string
		for name := range m.Commands {
			cmds = append(cmds, name)
		}
		skills = append(skills, skillInfo{
			Name:        m.Name,
			Version:     m.Version,
			Description: m.Description,
			Scopes:      m.Scopes,
			Commands:    cmds,
		})
	}

	return map[string]interface{}{"skills": skills, "count": len(skills)}, nil
}

func (s *Server) toolAuditQuery(args json.RawMessage) (interface{}, error) {
	var params struct {
		Limit int `json:"limit"`
	}
	if len(args) > 0 {
		json.Unmarshal(args, &params)
	}
	if params.Limit <= 0 {
		params.Limit = 20
	}
	if params.Limit > maxAuditQueryLimit {
		params.Limit = maxAuditQueryLimit
	}

	cfgDir, err := config.DefaultConfigDir()
	if err != nil {
		return nil, err
	}

	logPath := filepath.Join(cfgDir, "audit", "audit.log")
	entries, err := audit.ReadAll(logPath)
	if err != nil {
		return nil, err
	}

	// Return last N entries
	if len(entries) > params.Limit {
		entries = entries[len(entries)-params.Limit:]
	}

	return map[string]interface{}{"entries": entries, "total": len(entries)}, nil
}

func (s *Server) toolPosture() (interface{}, error) {
	return posture.Calculate()
}

func (s *Server) toolVerifyLogs() (interface{}, error) {
	cfgDir, err := config.DefaultConfigDir()
	if err != nil {
		return nil, err
	}

	logPath := filepath.Join(cfgDir, "audit", "audit.log")
	valid, err := audit.Verify(logPath)
	if err != nil {
		return map[string]interface{}{"valid": false, "error": err.Error()}, nil
	}
	return map[string]interface{}{"valid": valid}, nil
}

func (s *Server) toolCompliance() (interface{}, error) {
	cfg, err := config.LoadDefault()
	if err != nil {
		return nil, err
	}

	cfgDir, err := config.DefaultConfigDir()
	if err != nil {
		return nil, err
	}

	auditPath := filepath.Join(cfgDir, "audit", "audit.log")
	return compliance.Assess(cfg, auditPath)
}

func (s *Server) toolComplianceReport() (interface{}, error) {
	cfg, err := config.LoadDefault()
	if err != nil {
		return nil, err
	}

	cfgDir, err := config.DefaultConfigDir()
	if err != nil {
		return nil, err
	}

	auditPath := filepath.Join(cfgDir, "audit", "audit.log")
	return compliance.GenerateReport(cfg, auditPath)
}

func (s *Server) toolLineage(args json.RawMessage) (interface{}, error) {
	var params struct {
		Skill       string `json:"skill"`
		ExecutionID string `json:"execution_id"`
		Limit       int    `json:"limit"`
	}
	if len(args) > 0 {
		json.Unmarshal(args, &params)
	}
	if params.Limit <= 0 {
		params.Limit = 50
	}

	cfgDir, err := config.DefaultConfigDir()
	if err != nil {
		return nil, err
	}

	lineagePath := filepath.Join(cfgDir, "audit", "lineage.log")

	var records []lineage.Record

	switch {
	case params.ExecutionID != "":
		records, err = lineage.QueryByExecution(lineagePath, params.ExecutionID)
	case params.Skill != "":
		records, err = lineage.QueryBySkill(lineagePath, params.Skill)
	default:
		records, err = lineage.ReadAll(lineagePath)
	}
	if err != nil {
		return nil, err
	}

	if len(records) > params.Limit {
		records = records[len(records)-params.Limit:]
	}

	return map[string]interface{}{"records": records, "total": len(records)}, nil
}

func (s *Server) writeResponse(resp response) {
	data, _ := json.Marshal(resp)
	fmt.Fprintf(os.Stdout, "%s\n", data)
}

func (s *Server) writeError(id json.RawMessage, code int, message string) {
	resp := response{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &rpcError{Code: code, Message: message},
	}
	s.writeResponse(resp)
}
