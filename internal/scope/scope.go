// Package scope defines the capability-based permission model for AegisClaw.
package scope

import "fmt"

// Risk represents the risk level of a scope
type Risk int

const (
	RiskLow Risk = iota
	RiskMedium
	RiskHigh
	RiskCritical
)

func (r Risk) String() string {
	switch r {
	case RiskLow:
		return "low"
	case RiskMedium:
		return "medium"
	case RiskHigh:
		return "high"
	case RiskCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// Emoji returns a colored emoji representing the risk level
func (r Risk) Emoji() string {
	switch r {
	case RiskLow:
		return "🟢"
	case RiskMedium:
		return "🟡"
	case RiskHigh:
		return "🟠"
	case RiskCritical:
		return "🔴"
	default:
		return "⚪"
	}
}

// Scope represents a capability that a tool/skill can request
type Scope struct {
	Name      string // e.g., "email.send", "shell.exec"
	Resource  string // optional resource path, e.g., "/home/user/docs"
	RiskLevel Risk
}

// String returns a human-readable representation of the scope
func (s Scope) String() string {
	if s.Resource != "" {
		return fmt.Sprintf("%s:%s", s.Name, s.Resource)
	}
	return s.Name
}

// Predefined scopes
var (
	// Critical scopes - always require approval
	ShellExec = Scope{Name: "shell.exec", RiskLevel: RiskCritical}
	
	// High-risk scopes
	FilesWrite   = Scope{Name: "files.write", RiskLevel: RiskHigh}
	EmailSend    = Scope{Name: "email.send", RiskLevel: RiskHigh}
	SecretsAccess = Scope{Name: "secrets.access", RiskLevel: RiskHigh}
	
	// Medium-risk scopes
	HTTPRequest  = Scope{Name: "http.request", RiskLevel: RiskMedium}
	EmailRead    = Scope{Name: "email.read", RiskLevel: RiskMedium}
	CalendarRead = Scope{Name: "calendar.read", RiskLevel: RiskMedium}
	
	// Low-risk scopes
	FilesRead = Scope{Name: "files.read", RiskLevel: RiskLow}
)

// Registry holds all known scopes
var Registry = map[string]Scope{
	"shell.exec":     ShellExec,
	"files.write":    FilesWrite,
	"files.read":     FilesRead,
	"email.send":     EmailSend,
	"email.read":     EmailRead,
	"secrets.access": SecretsAccess,
	"http.request":   HTTPRequest,
	"calendar.read":  CalendarRead,
}

// Parse parses a scope string into a Scope struct
func Parse(s string) (Scope, error) {
	// Check if it's a known scope
	if scope, ok := Registry[s]; ok {
		return scope, nil
	}
	
	// Unknown scope - return with unknown risk
	return Scope{Name: s, RiskLevel: RiskMedium}, nil
}

// ScopeRequest represents a request for one or more scopes
type ScopeRequest struct {
	Scopes      []Scope
	Reason      string
	RequestedBy string // skill/tool name
}

// MaxRisk returns the highest risk level among the requested scopes
func (sr ScopeRequest) MaxRisk() Risk {
	maxRisk := RiskLow
	for _, s := range sr.Scopes {
		if s.RiskLevel > maxRisk {
			maxRisk = s.RiskLevel
		}
	}
	return maxRisk
}
