package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestHub_BroadcastNoClients(t *testing.T) {
	h := NewHub()
	// Should not panic with no clients
	h.Broadcast(WSEvent{Type: EventAudit, Data: "test"})
}

func TestHub_ClientCount(t *testing.T) {
	h := NewHub()
	if h.ClientCount() != 0 {
		t.Errorf("expected 0 clients, got %d", h.ClientCount())
	}
}

func TestHub_WebSocketConnection(t *testing.T) {
	h := NewHub()

	srv := httptest.NewServer(http.HandlerFunc(h.ServeWS))
	defer srv.Close()

	// Convert http URL to ws URL
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/ws"

	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial error: %v", err)
	}
	defer conn.Close()

	// Should receive welcome event
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read error: %v", err)
	}

	var evt WSEvent
	if err := json.Unmarshal(msg, &evt); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if evt.Type != EventStatus {
		t.Errorf("expected status event, got %s", evt.Type)
	}
}

func TestHub_BroadcastToClient(t *testing.T) {
	h := NewHub()

	srv := httptest.NewServer(http.HandlerFunc(h.ServeWS))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial error: %v", err)
	}
	defer conn.Close()

	// Read welcome
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	conn.ReadMessage()

	// Wait for registration to complete
	time.Sleep(50 * time.Millisecond)

	// Broadcast an event
	h.Broadcast(WSEvent{
		Type: EventAudit,
		Data: map[string]string{"action": "test_action"},
	})

	// Read broadcast
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read broadcast error: %v", err)
	}

	var evt WSEvent
	if err := json.Unmarshal(msg, &evt); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if evt.Type != EventAudit {
		t.Errorf("expected audit event, got %s", evt.Type)
	}
}
