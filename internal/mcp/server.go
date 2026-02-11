// Package mcp implements a Model Context Protocol server for AegisClaw.
// It allows AI assistants like Claude Code to interact with AegisClaw
// via the stdio transport.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/mackeh/AegisClaw/internal/audit"
	"github.com/mackeh/AegisClaw/internal/config"
	"github.com/mackeh/AegisClaw/internal/posture"
	"github.com/mackeh/AegisClaw/internal/skill"
)

// JSON-RPC 2.0 types
type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *rpcError   `json:"error,omitempty"`
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
	tools []Tool
}

// NewServer creates an MCP server with AegisClaw tools.
func NewServer() *Server {
	return &Server{
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
		},
	}
}

// Run starts the MCP server on stdio, reading JSON-RPC requests and writing responses.
func (s *Server) Run(ctx context.Context) error {
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
					"version": "0.5.1",
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
	default:
		return response{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32602, Message: fmt.Sprintf("Unknown tool: %s", params.Name)}}
	}

	if err != nil {
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

// Ensure io is used (it's used for doc comments about the transport)
var _ io.Reader
