package harness

import (
	"testing"
	"time"

	"github.com/mackeh/AegisClaw/internal/audit"
)

func TestSummarizeAudit(t *testing.T) {
	now := time.Now().UTC()
	entries := []audit.Entry{
		{Action: "harness.start", Timestamp: now},
		{Action: "harness.plane.network", Timestamp: now},
		{Action: "harness.plane.model", Timestamp: now},
		{Action: "llm.request", Timestamp: now},
		{Action: "mcp.tool_call", Timestamp: now},
		{Action: "mcp.tool_call", Timestamp: now},
		{Action: "harness.stop", Timestamp: now},
		{Action: "skill.exec", Timestamp: now}, // unrelated, ignored
	}

	s := SummarizeAudit(entries)
	if s.Sessions != 1 {
		t.Fatalf("expected 1 session, got %d", s.Sessions)
	}

	byPlane := map[string]PlaneStatus{}
	for _, p := range s.Planes {
		byPlane[p.Plane] = p
	}
	if len(s.Planes) != 4 {
		t.Fatalf("expected 4 planes, got %d", len(s.Planes))
	}
	if !byPlane["tools"].Active || byPlane["tools"].Events != 2 {
		t.Fatalf("tools plane wrong: %+v", byPlane["tools"])
	}
	if !byPlane["model"].Active || byPlane["model"].Events != 2 { // plane.model + llm.request
		t.Fatalf("model plane wrong: %+v", byPlane["model"])
	}
	if !byPlane["network"].Active || byPlane["network"].Events != 1 {
		t.Fatalf("network plane wrong: %+v", byPlane["network"])
	}
	if !byPlane["host"].Active { // start + stop
		t.Fatalf("host plane should be active: %+v", byPlane["host"])
	}
}

func TestSummarizeAuditEmpty(t *testing.T) {
	s := SummarizeAudit(nil)
	if s.Sessions != 0 || len(s.Planes) != 4 {
		t.Fatalf("empty summary should have 0 sessions and 4 planes, got %+v", s)
	}
	for _, p := range s.Planes {
		if p.Active {
			t.Fatalf("plane %s should be inactive with no audit data", p.Plane)
		}
	}
}
