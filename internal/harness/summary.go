package harness

import (
	"strings"
	"time"

	"github.com/mackeh/AegisClaw/internal/audit"
)

// PlaneStatus reports the activity of one enforcement plane, derived from the
// audit log.
type PlaneStatus struct {
	Plane    string `json:"plane"`  // tools | model | network | host
	Label    string `json:"label"`  // human-readable name
	Active   bool   `json:"active"` // any activity observed
	Events   int    `json:"events"` // count of related audit entries
	LastSeen string `json:"last_seen,omitempty"`
}

// Summary is the harness control-plane view used by the dashboard.
type Summary struct {
	Planes   []PlaneStatus `json:"planes"`
	Sessions int           `json:"sessions"` // number of agent launches (harness.start)
	LastSeen string        `json:"last_seen,omitempty"`
}

// planeForAction maps an audit action to the enforcement plane it belongs to.
func planeForAction(action string) Plane {
	switch {
	case action == "mcp.tool_call" || action == "mcp.tool_pin":
		return PlaneTools
	case action == "llm.request" || action == "llm.response" || action == "harness.plane.model":
		return PlaneModel
	case action == "harness.plane.network" || action == "network.egress":
		return PlaneNetwork
	case action == "harness.start" || action == "harness.stop" ||
		action == "harness.sandbox.recommended" || strings.HasPrefix(action, "kernel."):
		return PlaneHost
	default:
		return ""
	}
}

// SummarizeAudit derives per-plane activity and session counts from audit
// entries (typically the union of audit.log and mcp.log).
func SummarizeAudit(entries []audit.Entry) Summary {
	labels := map[Plane]string{
		PlaneTools:   "Tools (MCP gateway)",
		PlaneModel:   "Model (LLM proxy)",
		PlaneNetwork: "Network (egress proxy)",
		PlaneHost:    "Host (sandbox)",
	}
	order := []Plane{PlaneTools, PlaneModel, PlaneNetwork, PlaneHost}

	counts := map[Plane]int{}
	last := map[Plane]time.Time{}
	sessions := 0
	var overall time.Time

	for _, e := range entries {
		if e.Action == "harness.start" {
			sessions++
		}
		p := planeForAction(e.Action)
		if p == "" {
			continue
		}
		counts[p]++
		if e.Timestamp.After(last[p]) {
			last[p] = e.Timestamp
		}
		if e.Timestamp.After(overall) {
			overall = e.Timestamp
		}
	}

	planes := make([]PlaneStatus, 0, len(order))
	for _, p := range order {
		ps := PlaneStatus{Plane: string(p), Label: labels[p], Events: counts[p], Active: counts[p] > 0}
		if t := last[p]; !t.IsZero() {
			ps.LastSeen = t.UTC().Format(time.RFC3339)
		}
		planes = append(planes, ps)
	}

	s := Summary{Planes: planes, Sessions: sessions}
	if !overall.IsZero() {
		s.LastSeen = overall.UTC().Format(time.RFC3339)
	}
	return s
}
