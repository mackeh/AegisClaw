package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
)

// Downstream is a real MCP server the gateway forwards (vetted) calls to. The
// gateway speaks MCP to the agent on one side and to a Downstream on the other.
type Downstream interface {
	Initialize(ctx context.Context, params json.RawMessage) (json.RawMessage, error)
	ListTools(ctx context.Context) ([]Tool, error)
	CallTool(ctx context.Context, name string, args json.RawMessage) (json.RawMessage, error)
	Close() error
}

// rpcConn is a minimal synchronous JSON-RPC 2.0 client over a line-delimited
// reader/writer pair. Calls are serialized; the connection reads until it sees
// the response with the matching id, skipping notifications and unrelated lines.
type rpcConn struct {
	mu  sync.Mutex
	w   io.Writer
	dec *bufio.Scanner
	id  int
}

func newRPCConn(w io.Writer, r io.Reader) *rpcConn {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	return &rpcConn{w: w, dec: sc}
}

func (c *rpcConn) call(method string, params json.RawMessage) (json.RawMessage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.id++
	id := c.id
	reqObj := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if len(params) > 0 {
		reqObj["params"] = params
	}
	data, _ := json.Marshal(reqObj)
	if _, err := c.w.Write(append(data, '\n')); err != nil {
		return nil, fmt.Errorf("write to downstream: %w", err)
	}

	for c.dec.Scan() {
		line := c.dec.Bytes()
		if len(line) == 0 {
			continue
		}
		var resp struct {
			ID     json.RawMessage `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  *rpcError       `json:"error"`
		}
		if err := json.Unmarshal(line, &resp); err != nil {
			continue // not a JSON-RPC message we understand
		}
		if len(resp.ID) == 0 {
			continue // notification; ignore
		}
		var gotID int
		if json.Unmarshal(resp.ID, &gotID) != nil || gotID != id {
			continue // response to a different request
		}
		if resp.Error != nil {
			return nil, fmt.Errorf("downstream error %d: %s", resp.Error.Code, resp.Error.Message)
		}
		return resp.Result, nil
	}
	if err := c.dec.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("downstream closed before responding to %s", method)
}

// StdioDownstream spawns an MCP server as a child process and speaks JSON-RPC
// over its stdin/stdout. This is how most local MCP servers run, and it lets
// the gateway sandbox or supervise the downstream itself in future work.
type StdioDownstream struct {
	cmd  *exec.Cmd
	conn *rpcConn
}

// NewStdioDownstream starts the given command as a downstream MCP server.
func NewStdioDownstream(ctx context.Context, name string, args ...string) (*StdioDownstream, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start downstream %q: %w", name, err)
	}
	return &StdioDownstream{cmd: cmd, conn: newRPCConn(stdin, stdout)}, nil
}

func (d *StdioDownstream) Initialize(ctx context.Context, params json.RawMessage) (json.RawMessage, error) {
	return d.conn.call("initialize", params)
}

func (d *StdioDownstream) ListTools(ctx context.Context) ([]Tool, error) {
	raw, err := d.conn.call("tools/list", nil)
	if err != nil {
		return nil, err
	}
	var res struct {
		Tools []Tool `json:"tools"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("parse downstream tools/list: %w", err)
	}
	return res.Tools, nil
}

func (d *StdioDownstream) CallTool(ctx context.Context, name string, args json.RawMessage) (json.RawMessage, error) {
	p, _ := json.Marshal(map[string]any{"name": name, "arguments": args})
	return d.conn.call("tools/call", p)
}

func (d *StdioDownstream) Close() error {
	if d.cmd.Process != nil {
		_ = d.cmd.Process.Kill()
	}
	return nil
}
