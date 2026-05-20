package agent

import (
	"fmt"
	"io"
	"strings"

	"github.com/mackeh/AegisClaw/internal/audit"
	"github.com/mackeh/AegisClaw/internal/config"
	"github.com/mackeh/AegisClaw/internal/guardrails"
)

// GuardrailMode controls how the agent reacts to guardrail violations found in
// a skill's output.
type GuardrailMode string

const (
	// GuardrailOff disables output scanning entirely.
	GuardrailOff GuardrailMode = "off"
	// GuardrailWarn scans and reports violations but still returns the output.
	GuardrailWarn GuardrailMode = "warn"
	// GuardrailBlock withholds output that carries a critical/high violation.
	GuardrailBlock GuardrailMode = "block"
)

// guardrailMode resolves the effective guardrail mode from configuration.
// An unset or unrecognised mode defaults to GuardrailWarn so skill output is
// always scanned unless an operator explicitly opts out.
func guardrailMode(cfg *config.Config) GuardrailMode {
	if cfg == nil {
		return GuardrailWarn
	}
	switch GuardrailMode(strings.ToLower(strings.TrimSpace(cfg.Guardrails.Mode))) {
	case GuardrailOff:
		return GuardrailOff
	case GuardrailBlock:
		return GuardrailBlock
	default:
		return GuardrailWarn
	}
}

// inspectSkillOutput scans a skill's captured output for indirect prompt
// injection — instructions smuggled into returned data that would hijack the
// agent if fed back into the model. Violations are written to the audit log.
// It reports the guardrail result and whether the output should be treated as
// blocked under the given mode.
func inspectSkillOutput(mode GuardrailMode, skillName, output string, logger *audit.Logger) (*guardrails.Result, bool) {
	if mode == GuardrailOff || output == "" {
		return nil, false
	}

	res := guardrails.NewEngine().CheckData("skill:"+skillName, output)
	if len(res.Violations) == 0 {
		return res, false
	}

	if logger != nil {
		for _, v := range res.Violations {
			_ = logger.Log("guardrail.violation", nil, string(v.Severity), skillName, map[string]any{
				"rule":    v.Rule,
				"message": v.Message,
				"source":  res.Source,
			})
		}
	}

	blocked := mode == GuardrailBlock && !res.Allowed
	return res, blocked
}

// reportViolations prints a human-readable summary of guardrail violations.
func reportViolations(w io.Writer, skillName string, res *guardrails.Result) {
	fmt.Fprintf(w, "⚠️  Guardrails flagged %d issue(s) in '%s' output — possible prompt injection in returned data:\n",
		len(res.Violations), skillName)
	for _, v := range res.Violations {
		fmt.Fprintf(w, "   [%s] %s: %s\n", strings.ToUpper(string(v.Severity)), v.Rule, v.Message)
	}
}
