package mcp

import (
	"bufio"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

// scriptedServer reads JSON-RPC requests from r and writes canned responses to
// w, echoing the request id. It lets us exercise rpcConn framing/correlation
// without spawning a real process.
func scriptedServer(r io.Reader, w io.Writer, handler func(method string) any) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if json.Unmarshal(line, &req) != nil {
			continue
		}
		resp := map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": handler(req.Method)}
		data, _ := json.Marshal(resp)
		_, _ = w.Write(append(data, '\n'))
	}
}

func TestRPCConnCallCorrelatesResponses(t *testing.T) {
	csR, csW := io.Pipe() // client -> server
	scR, scW := io.Pipe() // server -> client

	go scriptedServer(csR, scW, func(method string) any {
		if method == "tools/list" {
			return map[string]any{"tools": []Tool{{Name: "echo", Description: "echoes"}}}
		}
		return map[string]any{"ok": method}
	})

	conn := newRPCConn(csW, scR)

	raw, err := conn.call("tools/list", nil)
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if !strings.Contains(string(raw), "echo") {
		t.Fatalf("unexpected result: %s", raw)
	}

	// A second call must correlate to the second response, proving id matching
	// works across sequential calls.
	raw2, err := conn.call("ping", nil)
	if err != nil {
		t.Fatalf("call 2: %v", err)
	}
	if !strings.Contains(string(raw2), "ping") {
		t.Fatalf("unexpected result 2: %s", raw2)
	}
}
