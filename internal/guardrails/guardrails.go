// Package guardrails provides input/output safety rails for LLM prompts.
// It scans prompts and responses for injection attacks, sensitive data leaks,
// and policy violations before they reach or leave the model.
package guardrails

import (
	"fmt"
	"regexp"
	"strings"
)

// Severity indicates how severe a guardrail violation is.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Violation represents a detected guardrail violation.
type Violation struct {
	Rule     string   `json:"rule"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
	Span     [2]int   `json:"span,omitempty"` // character offsets [start, end]
}

// Result holds the outcome of a guardrail check.
type Result struct {
	Allowed    bool        `json:"allowed"`
	Violations []Violation `json:"violations,omitempty"`
	Sanitized  string      `json:"sanitized,omitempty"` // cleaned text if output mode
}

// Rule is a single guardrail check.
type Rule struct {
	Name     string
	Severity Severity
	CheckFn  func(text string) []Violation
}

// Engine evaluates text against a set of guardrail rules.
type Engine struct {
	inputRules  []Rule
	outputRules []Rule
}

// NewEngine creates a guardrail engine with default rules.
func NewEngine() *Engine {
	e := &Engine{}
	e.inputRules = defaultInputRules()
	e.outputRules = defaultOutputRules()
	return e
}

// CheckInput validates a prompt before sending to the LLM.
func (e *Engine) CheckInput(text string) *Result {
	var violations []Violation
	for _, r := range e.inputRules {
		violations = append(violations, r.CheckFn(text)...)
	}

	return &Result{
		Allowed:    !hasCriticalOrHigh(violations),
		Violations: violations,
	}
}

// CheckOutput validates an LLM response before returning to the user.
func (e *Engine) CheckOutput(text string) *Result {
	var violations []Violation
	for _, r := range e.outputRules {
		violations = append(violations, r.CheckFn(text)...)
	}

	sanitized := text
	if len(violations) > 0 {
		sanitized = sanitizeOutput(text, violations)
	}

	return &Result{
		Allowed:    !hasCriticalOrHigh(violations),
		Violations: violations,
		Sanitized:  sanitized,
	}
}

// AddInputRule adds a custom rule for input checking.
func (e *Engine) AddInputRule(r Rule) {
	e.inputRules = append(e.inputRules, r)
}

// AddOutputRule adds a custom rule for output checking.
func (e *Engine) AddOutputRule(r Rule) {
	e.outputRules = append(e.outputRules, r)
}

func hasCriticalOrHigh(violations []Violation) bool {
	for _, v := range violations {
		if v.Severity == SeverityCritical || v.Severity == SeverityHigh {
			return true
		}
	}
	return false
}

// --- Default Input Rules ---

func defaultInputRules() []Rule {
	return []Rule{
		{Name: "prompt_injection", Severity: SeverityCritical, CheckFn: checkPromptInjection},
		{Name: "jailbreak_attempt", Severity: SeverityHigh, CheckFn: checkJailbreak},
		{Name: "sensitive_data_input", Severity: SeverityMedium, CheckFn: checkSensitiveDataInput},
	}
}

var injectionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)`),
	regexp.MustCompile(`(?i)you\s+are\s+now\s+(a|an|the)\s+`),
	regexp.MustCompile(`(?i)system\s*:\s*you\s+are`),
	regexp.MustCompile(`(?i)forget\s+(everything|all)\s+(you|that)`),
	regexp.MustCompile(`(?i)new\s+instructions?\s*:`),
	regexp.MustCompile(`(?i)override\s+(your|the|all)\s+(instructions|rules|guidelines)`),
	regexp.MustCompile(`(?i)\bdo\s+anything\s+now\b`),
}

func checkPromptInjection(text string) []Violation {
	var violations []Violation
	for _, pat := range injectionPatterns {
		loc := pat.FindStringIndex(text)
		if loc != nil {
			violations = append(violations, Violation{
				Rule:     "prompt_injection",
				Severity: SeverityCritical,
				Message:  fmt.Sprintf("Potential prompt injection detected: %q", text[loc[0]:loc[1]]),
				Span:     [2]int{loc[0], loc[1]},
			})
		}
	}
	return violations
}

var jailbreakPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bDAN\s+mode\b`),
	regexp.MustCompile(`(?i)developer\s+mode\s+(enabled|on|activated)`),
	regexp.MustCompile(`(?i)act\s+as\s+an?\s+(unrestricted|unfiltered|uncensored)`),
	regexp.MustCompile(`(?i)pretend\s+(you|that)\s+(have\s+no|don'?t\s+have)\s+(restrictions|limits|rules)`),
}

func checkJailbreak(text string) []Violation {
	var violations []Violation
	for _, pat := range jailbreakPatterns {
		loc := pat.FindStringIndex(text)
		if loc != nil {
			violations = append(violations, Violation{
				Rule:     "jailbreak_attempt",
				Severity: SeverityHigh,
				Message:  fmt.Sprintf("Jailbreak pattern detected: %q", text[loc[0]:loc[1]]),
				Span:     [2]int{loc[0], loc[1]},
			})
		}
	}
	return violations
}

var sensitiveInputPatterns = []*regexp.Regexp{
	// API keys, tokens
	regexp.MustCompile(`(?i)(sk-[a-zA-Z0-9_-]{20,})`),
	regexp.MustCompile(`(?i)(ghp_[a-zA-Z0-9]{36,})`),
	regexp.MustCompile(`(?i)(AKIA[0-9A-Z]{16})`),
	// Credit card numbers (basic Luhn-eligible patterns)
	regexp.MustCompile(`\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`),
	// SSN
	regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
}

func checkSensitiveDataInput(text string) []Violation {
	var violations []Violation
	for _, pat := range sensitiveInputPatterns {
		loc := pat.FindStringIndex(text)
		if loc != nil {
			violations = append(violations, Violation{
				Rule:     "sensitive_data_input",
				Severity: SeverityMedium,
				Message:  "Potentially sensitive data detected in prompt input",
				Span:     [2]int{loc[0], loc[1]},
			})
		}
	}
	return violations
}

// --- Default Output Rules ---

func defaultOutputRules() []Rule {
	return []Rule{
		{Name: "secret_leak", Severity: SeverityCritical, CheckFn: checkSecretLeak},
		{Name: "harmful_instruction", Severity: SeverityHigh, CheckFn: checkHarmfulInstruction},
	}
}

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(sk-[a-zA-Z0-9_-]{20,})`),
	regexp.MustCompile(`(?i)(ghp_[a-zA-Z0-9]{36,})`),
	regexp.MustCompile(`(?i)(AKIA[0-9A-Z]{16})`),
	regexp.MustCompile(`(?i)password\s*[:=]\s*["']?([^\s"']{8,})`),
}

func checkSecretLeak(text string) []Violation {
	var violations []Violation
	for _, pat := range secretPatterns {
		loc := pat.FindStringIndex(text)
		if loc != nil {
			violations = append(violations, Violation{
				Rule:     "secret_leak",
				Severity: SeverityCritical,
				Message:  "Potential secret/credential detected in output",
				Span:     [2]int{loc[0], loc[1]},
			})
		}
	}
	return violations
}

var harmfulPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)rm\s+-rf\s+/[^a-z]`),
	regexp.MustCompile(`(?i):(){ :\|:& };:`),                                   // fork bomb
	regexp.MustCompile(`(?i)curl\s+[^\s]+\s*\|\s*(?:sudo\s+)?(?:bash|sh)\b`),   // pipe to shell
	regexp.MustCompile(`(?i)wget\s+[^\s]+\s*&&\s*(?:sudo\s+)?(?:bash|sh)\b`),   // download and execute
}

func checkHarmfulInstruction(text string) []Violation {
	var violations []Violation
	for _, pat := range harmfulPatterns {
		loc := pat.FindStringIndex(text)
		if loc != nil {
			violations = append(violations, Violation{
				Rule:     "harmful_instruction",
				Severity: SeverityHigh,
				Message:  fmt.Sprintf("Potentially harmful instruction detected: %q", text[loc[0]:loc[1]]),
				Span:     [2]int{loc[0], loc[1]},
			})
		}
	}
	return violations
}

// sanitizeOutput redacts detected secrets from output text.
func sanitizeOutput(text string, violations []Violation) string {
	result := text
	for _, v := range violations {
		if v.Rule == "secret_leak" && v.Span[1] > v.Span[0] && v.Span[1] <= len(text) {
			secret := text[v.Span[0]:v.Span[1]]
			redacted := secret[:4] + strings.Repeat("*", len(secret)-4)
			result = strings.Replace(result, secret, redacted, 1)
		}
	}
	return result
}
