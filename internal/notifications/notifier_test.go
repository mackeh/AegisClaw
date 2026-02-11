package notifications

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestWebhookNotifier_Send(t *testing.T) {
	var receivedBody []byte
	var receivedSig string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedSig = r.Header.Get("X-AegisClaw-Signature")
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := NewWebhookNotifier(srv.URL, "test-secret", []Event{EventActionDenied})

	payload := Payload{
		Event:     EventActionDenied,
		Timestamp: time.Now(),
		Skill:     "test-skill",
		Decision:  "deny",
	}

	err := n.Send(context.Background(), payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(receivedBody) == 0 {
		t.Fatal("no body received")
	}

	if receivedSig == "" {
		t.Fatal("no HMAC signature received")
	}

	var got Payload
	if err := json.Unmarshal(receivedBody, &got); err != nil {
		t.Fatalf("failed to unmarshal body: %v", err)
	}
	if got.Skill != "test-skill" {
		t.Errorf("expected skill 'test-skill', got '%s'", got.Skill)
	}
}

func TestWebhookNotifier_Handles(t *testing.T) {
	n := NewWebhookNotifier("http://example.com", "", []Event{EventActionDenied, EventEmergencyLockdown})

	if !n.Handles(EventActionDenied) {
		t.Error("expected to handle EventActionDenied")
	}
	if !n.Handles(EventEmergencyLockdown) {
		t.Error("expected to handle EventEmergencyLockdown")
	}
	if n.Handles(EventSkillCompleted) {
		t.Error("should not handle EventSkillCompleted")
	}
}

func TestWebhookNotifier_HandlesAll(t *testing.T) {
	n := NewWebhookNotifier("http://example.com", "", nil)
	if !n.Handles(EventSkillCompleted) {
		t.Error("empty events list should handle all events")
	}
}

func TestSlackNotifier_Send(t *testing.T) {
	var receivedBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := NewSlackNotifier(srv.URL, []Event{EventApprovalPending})

	payload := Payload{
		Event:     EventApprovalPending,
		Timestamp: time.Now(),
		Skill:     "web-search",
		Command:   "search",
	}

	err := n.Send(context.Background(), payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var msg slackMessage
	if err := json.Unmarshal(receivedBody, &msg); err != nil {
		t.Fatalf("failed to unmarshal slack message: %v", err)
	}
	if msg.Text == "" {
		t.Error("slack message text is empty")
	}
}

func TestDispatcher_Notify(t *testing.T) {
	called := make(chan bool, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called <- true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	configs := []NotifierConfig{
		{
			Type:   "webhook",
			URL:    srv.URL,
			Events: []Event{EventActionDenied},
		},
	}

	d := NewDispatcher(configs)
	d.Notify(context.Background(), Payload{
		Event: EventActionDenied,
		Skill: "test",
	})

	select {
	case <-called:
		// success
	case <-time.After(2 * time.Second):
		t.Error("webhook was not called within timeout")
	}
}

func TestFormatSlackMessage(t *testing.T) {
	tests := []struct {
		event Event
		want  string
	}{
		{EventApprovalPending, "Approval Pending"},
		{EventActionDenied, "Action Denied"},
		{EventEmergencyLockdown, "EMERGENCY LOCKDOWN"},
		{EventSkillCompleted, "Skill Completed"},
		{EventSecretLeakDetected, "Secret Leak Detected"},
	}

	for _, tt := range tests {
		msg := formatSlackMessage(Payload{Event: tt.event, Skill: "s"})
		if msg.Text == "" {
			t.Errorf("empty message for event %s", tt.event)
		}
	}
}
