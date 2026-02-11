package mcp

import (
	"context"
	"encoding/json"
	"testing"
)

func TestNewServer(t *testing.T) {
	s := NewServer()
	if s == nil {
		t.Fatal("expected non-nil server")
	}
	if len(s.tools) != 4 {
		t.Errorf("expected 4 tools, got %d", len(s.tools))
	}
}

func TestHandleRequest_Initialize(t *testing.T) {
	s := NewServer()
	req := request{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "initialize",
	}

	resp := s.handleRequest(context.Background(), req)
	if resp.Error != nil {
		t.Fatalf("unexpected error: %s", resp.Error.Message)
	}

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}

	serverInfo := result["serverInfo"].(map[string]interface{})
	if serverInfo["name"] != "aegisclaw" {
		t.Errorf("expected name 'aegisclaw', got %v", serverInfo["name"])
	}
}

func TestHandleRequest_ToolsList(t *testing.T) {
	s := NewServer()
	req := request{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`2`),
		Method:  "tools/list",
	}

	resp := s.handleRequest(context.Background(), req)
	if resp.Error != nil {
		t.Fatalf("unexpected error: %s", resp.Error.Message)
	}

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}

	tools := result["tools"].([]Tool)
	if len(tools) != 4 {
		t.Errorf("expected 4 tools, got %d", len(tools))
	}

	toolNames := map[string]bool{}
	for _, tool := range tools {
		toolNames[tool.Name] = true
	}

	expected := []string{"aegisclaw_list_skills", "aegisclaw_audit_query", "aegisclaw_posture", "aegisclaw_verify_logs"}
	for _, name := range expected {
		if !toolNames[name] {
			t.Errorf("expected tool '%s' not found", name)
		}
	}
}

func TestHandleRequest_MethodNotFound(t *testing.T) {
	s := NewServer()
	req := request{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`3`),
		Method:  "nonexistent/method",
	}

	resp := s.handleRequest(context.Background(), req)
	if resp.Error == nil {
		t.Fatal("expected error for unknown method")
	}
	if resp.Error.Code != -32601 {
		t.Errorf("expected error code -32601, got %d", resp.Error.Code)
	}
}

func TestHandleToolCall_UnknownTool(t *testing.T) {
	s := NewServer()
	params, _ := json.Marshal(map[string]interface{}{
		"name":      "nonexistent_tool",
		"arguments": map[string]interface{}{},
	})
	req := request{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`4`),
		Method:  "tools/call",
		Params:  json.RawMessage(params),
	}

	resp := s.handleRequest(context.Background(), req)
	if resp.Error == nil {
		t.Fatal("expected error for unknown tool")
	}
	if resp.Error.Code != -32602 {
		t.Errorf("expected error code -32602, got %d", resp.Error.Code)
	}
}

func TestHandleToolCall_InvalidParams(t *testing.T) {
	s := NewServer()
	req := request{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`5`),
		Method:  "tools/call",
		Params:  json.RawMessage(`invalid json`),
	}

	resp := s.handleRequest(context.Background(), req)
	if resp.Error == nil {
		t.Fatal("expected error for invalid params")
	}
}
