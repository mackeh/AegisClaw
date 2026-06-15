// Package compliance maps AegisClaw controls to the OWASP Top 10 for
// Agentic Applications (ASI01–ASI10) and generates compliance assessments.
package compliance

import (
	"time"

	"github.com/mackeh/AegisClaw/internal/audit"
	"github.com/mackeh/AegisClaw/internal/config"
	"github.com/mackeh/AegisClaw/internal/posture"
)

// ASI identifiers from the OWASP Top 10 for Agentic Applications.
const (
	ASI01 = "ASI01" // Agent Goal Hijack
	ASI02 = "ASI02" // Tool Misuse & Exploitation
	ASI03 = "ASI03" // Identity & Privilege Abuse
	ASI04 = "ASI04" // Agentic Supply Chain Vulnerabilities
	ASI05 = "ASI05" // Unexpected Code Execution
	ASI06 = "ASI06" // Memory & Context Poisoning
	ASI07 = "ASI07" // Insecure Inter-Agent Communication
	ASI08 = "ASI08" // Cascading Failures
	ASI09 = "ASI09" // Human-Agent Trust Exploitation
	ASI10 = "ASI10" // Rogue Agents
)

// Coverage represents whether a control is fully, partially, or not covered.
type Coverage string

const (
	CoverageFull    Coverage = "full"
	CoveragePartial Coverage = "partial"
	CoverageNone    Coverage = "none"
)

// Control describes a single OWASP ASI control and its AegisClaw mapping.
type Control struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Coverage    Coverage `json:"coverage"`
	Controls    []string `json:"controls"`       // AegisClaw features addressing this risk
	Gaps        []string `json:"gaps,omitempty"` // Missing capabilities
	Score       int      `json:"score"`          // 0-100
}

// Assessment is the full OWASP ASI compliance report.
type Assessment struct {
	Timestamp    time.Time      `json:"timestamp"`
	Framework    string         `json:"framework"`
	Version      string         `json:"version"`
	Controls     []Control      `json:"controls"`
	OverallScore int            `json:"overall_score"` // 0-100
	OverallGrade string         `json:"overall_grade"` // A-F
	PostureScore *posture.Score `json:"posture_score,omitempty"`
}

// Assess evaluates the current AegisClaw installation against OWASP ASI.
func Assess(cfg *config.Config, auditPath string) (*Assessment, error) {
	controls := buildControlMap(cfg, auditPath)

	total := 0
	for _, c := range controls {
		total += c.Score
	}
	overall := total / len(controls)

	ps, _ := posture.Calculate()

	return &Assessment{
		Timestamp:    time.Now().UTC(),
		Framework:    "OWASP Top 10 for Agentic Applications",
		Version:      "2026",
		Controls:     controls,
		OverallScore: overall,
		OverallGrade: gradeFromScore(overall),
		PostureScore: ps,
	}, nil
}

func buildControlMap(cfg *config.Config, auditPath string) []Control {
	hasPolicy := cfg.Security.RequireApproval
	hasAudit := cfg.Security.AuditEnabled
	hasSandbox := cfg.Security.SandboxBackend != ""
	hasNetwork := cfg.Network.DefaultDeny || len(cfg.Network.Allowlist) > 0
	hasApproval := cfg.Security.RequireApproval

	auditVerified := false
	if hasAudit {
		if valid, err := audit.Verify(auditPath); err == nil && valid {
			auditVerified = true
		}
	}

	return []Control{
		{
			ID:          ASI01,
			Name:        "Agent Goal Hijack",
			Description: "Attackers redirect agent objectives via manipulated instructions, tool outputs, or external content",
			Coverage:    coverageIf(hasPolicy && hasApproval, CoveragePartial, CoverageNone),
			Controls:    filterPresent(hasPolicy, "OPA policy evaluation", hasApproval, "Human-in-the-loop approval", hasAudit, "Tamper-evident audit logging"),
			Gaps:        filterAbsent(!true, "", true, "Goal integrity hash verification", true, "Objective drift detection"),
			Score:       scoreFromControls(hasPolicy, hasApproval, false),
		},
		{
			ID:          ASI02,
			Name:        "Tool Misuse & Exploitation",
			Description: "Agents misuse legitimate tools due to prompt injection, misalignment, or unsafe delegation",
			Coverage:    coverageIf(hasPolicy && hasSandbox, CoverageFull, coverageIf(hasPolicy || hasSandbox, CoveragePartial, CoverageNone)),
			Controls:    filterPresent(hasPolicy, "OPA scope-based policy engine", hasSandbox, "Sandboxed execution environment", hasApproval, "Approval for high-risk scopes", hasNetwork, "Network egress filtering"),
			Gaps:        nil,
			Score:       scoreFromMulti(hasPolicy, hasSandbox, hasApproval, hasNetwork),
		},
		{
			ID:          ASI03,
			Name:        "Identity & Privilege Abuse",
			Description: "Exploiting inherited/cached credentials, delegated permissions, or agent-to-agent trust",
			Coverage:    coverageIf(hasPolicy, CoveragePartial, CoverageNone),
			Controls:    filterPresent(hasPolicy, "Scope-based capability model with risk levels", true, "Least-privilege default-deny posture", true, "RBAC API authentication (admin/operator/viewer)"),
			Gaps:        filterAbsent(true, "OIDC/SAML identity federation", true, "Non-human identity lifecycle management", true, "Short-lived scoped credentials"),
			Score:       scoreFromControls(hasPolicy, true, false),
		},
		{
			ID:          ASI04,
			Name:        "Agentic Supply Chain Vulnerabilities",
			Description: "Malicious or tampered tools, descriptors, models, or agent personas compromise execution",
			Coverage:    CoveragePartial,
			Controls:    []string{"Ed25519 skill manifest signature verification", "Skill registry with trust keys"},
			Gaps:        []string{"Sigstore/Cosign keyless signing", "SLSA provenance attestations", "Skill SBOM generation"},
			Score:       50,
		},
		{
			ID:          ASI05,
			Name:        "Unexpected Code Execution",
			Description: "Agents generate or execute attacker-controlled code",
			Coverage:    coverageIf(hasSandbox, CoverageFull, CoveragePartial),
			Controls:    filterPresent(hasSandbox, "Hardened Docker sandbox (dropped caps, read-only rootfs, resource limits)", true, "gVisor/Kata/Firecracker runtime options", hasNetwork, "Network egress proxy with domain allowlists", hasPolicy, "Policy-gated shell.exec scope"),
			Gaps:        nil,
			Score:       scoreFromMulti(hasSandbox, hasNetwork, hasPolicy, true),
		},
		{
			ID:          ASI06,
			Name:        "Memory & Context Poisoning",
			Description: "Persistent corruption of agent memory, RAG stores, or contextual knowledge",
			Coverage:    CoverageNone,
			Controls:    filterPresent(hasAudit, "Audit trail of all agent interactions"),
			Gaps:        []string{"Context integrity verification", "Memory state signing", "RAG store access controls"},
			Score:       boolScore(hasAudit, 15),
		},
		{
			ID:          ASI07,
			Name:        "Insecure Inter-Agent Communication",
			Description: "Messages between agents vulnerable to interception, spoofing, or replay attacks",
			Coverage:    CoveragePartial,
			Controls:    []string{"Cluster gRPC communication layer", "Policy sync between leader/followers"},
			Gaps:        []string{"mTLS for inter-node communication", "Message signing between agents", "A2A protocol support"},
			Score:       35,
		},
		{
			ID:          ASI08,
			Name:        "Cascading Failures",
			Description: "Single agent faults propagating across networks into system-wide disasters",
			Coverage:    CoveragePartial,
			Controls:    filterPresent(true, "Emergency lockdown / panic button", true, "Per-sandbox resource limits (512MB, 1 CPU, 100 PIDs)", hasSandbox, "Process isolation via containerization"),
			Gaps:        []string{"Circuit breaker patterns in cluster layer", "Automatic failure rate monitoring", "Blast radius containment policies"},
			Score:       40,
		},
		{
			ID:          ASI09,
			Name:        "Human-Agent Trust Exploitation",
			Description: "Agents leveraging anthropomorphism or authority bias to manipulate humans",
			Coverage:    coverageIf(hasApproval, CoveragePartial, CoverageNone),
			Controls:    filterPresent(hasApproval, "Explicit human-in-the-loop approval with risk context", hasAudit, "Full audit trail of approval decisions"),
			Gaps:        []string{"Agent output content analysis", "Social engineering pattern detection", "Approval fatigue monitoring"},
			Score:       boolScore(hasApproval, 35),
		},
		{
			ID:          ASI10,
			Name:        "Rogue Agents",
			Description: "Agents deviating from intended functions due to misalignment, acting as insider threats",
			Coverage:    coverageIf(hasAudit && auditVerified, CoveragePartial, CoverageNone),
			Controls:    filterPresent(hasAudit, "Tamper-evident hash-chained audit log", auditVerified, "Audit chain integrity verification", true, "eBPF kernel-level runtime monitoring", true, "Security posture scoring"),
			Gaps:        []string{"Behavioral baseline profiling", "Anomaly detection on agent behavior", "Automated rogue agent containment"},
			Score:       boolScore(hasAudit && auditVerified, 40),
		},
	}
}

// helpers

func coverageIf(cond bool, yes, no Coverage) Coverage {
	if cond {
		return yes
	}
	return no
}

func filterPresent(pairs ...interface{}) []string {
	var out []string
	for i := 0; i+1 < len(pairs); i += 2 {
		if b, ok := pairs[i].(bool); ok && b {
			if s, ok := pairs[i+1].(string); ok && s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

func filterAbsent(pairs ...interface{}) []string {
	var out []string
	for i := 0; i+1 < len(pairs); i += 2 {
		if b, ok := pairs[i].(bool); ok && b {
			if s, ok := pairs[i+1].(string); ok && s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

func scoreFromControls(a, b, c bool) int {
	n := 0
	for _, v := range []bool{a, b, c} {
		if v {
			n++
		}
	}
	return n * 100 / 3
}

func scoreFromMulti(vals ...bool) int {
	n := 0
	for _, v := range vals {
		if v {
			n++
		}
	}
	return n * 100 / len(vals)
}

func boolScore(v bool, score int) int {
	if v {
		return score
	}
	return 0
}

func gradeFromScore(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 75:
		return "B"
	case score >= 60:
		return "C"
	case score >= 40:
		return "D"
	default:
		return "F"
	}
}
