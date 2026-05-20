// Package guardrails provides input/output safety rails for LLM prompts.
// It scans prompts, responses, and untrusted data the agent ingests for
// injection attacks, sensitive data leaks, and policy violations before they
// reach or leave the model.
//
// Detection is evasion-resistant: every check runs against the original text
// plus normalised variants that neutralise invisible characters, homoglyphs,
// letter-spacing, and base64/hex encoding (see normalize.go).
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
	Source     string      `json:"source,omitempty"`    // origin label for data checks
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
	dataRules   []Rule
}

// NewEngine creates a guardrail engine with default rules.
func NewEngine() *Engine {
	return &Engine{
		inputRules:  defaultInputRules(),
		outputRules: defaultOutputRules(),
		dataRules:   defaultDataRules(),
	}
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

// CheckData scans untrusted content the agent ingests — tool outputs, fetched
// web pages, retrieved documents, file contents — for indirect prompt
// injection: instructions smuggled into data that try to hijack the agent.
// source labels where the content came from for the audit trail.
func (e *Engine) CheckData(source, text string) *Result {
	var violations []Violation
	for _, r := range e.dataRules {
		violations = append(violations, r.CheckFn(text)...)
	}
	return &Result{
		Allowed:    !hasCriticalOrHigh(violations),
		Violations: violations,
		Source:     source,
	}
}

// AddInputRule adds a custom rule for input checking.
func (e *Engine) AddInputRule(r Rule) { e.inputRules = append(e.inputRules, r) }

// AddOutputRule adds a custom rule for output checking.
func (e *Engine) AddOutputRule(r Rule) { e.outputRules = append(e.outputRules, r) }

// AddDataRule adds a custom rule for untrusted-data checking.
func (e *Engine) AddDataRule(r Rule) { e.dataRules = append(e.dataRules, r) }

func hasCriticalOrHigh(violations []Violation) bool {
	for _, v := range violations {
		if v.Severity == SeverityCritical || v.Severity == SeverityHigh {
			return true
		}
	}
	return false
}

// scanPatterns matches every pattern against all evasion-resistant variants of
// text and emits at most one violation per pattern.
func scanPatterns(text, rule string, sev Severity, patterns []*regexp.Regexp, label string) []Violation {
	st := newScanText(text)
	var violations []Violation
	for _, pat := range patterns {
		span, matched, evaded := st.find(pat)
		if !matched {
			continue
		}
		msg := label
		if evaded {
			msg += " detected (obfuscated: invisible characters, homoglyphs, encoding, or letter-spacing)"
		} else {
			msg += fmt.Sprintf(" detected: %q", text[span[0]:span[1]])
		}
		violations = append(violations, Violation{Rule: rule, Severity: sev, Message: msg, Span: span})
	}
	return violations
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
	regexp.MustCompile(`(?i)ignore\s+(all\s+)?(previous|prior|above|earlier|the\s+above)\s+(instructions|prompts|rules|messages|context)`),
	regexp.MustCompile(`(?i)disregard\s+(all\s+)?(previous|prior|above|earlier|the\s+above)\s+(instructions|prompts|rules|messages|context)`),
	regexp.MustCompile(`(?i)you\s+are\s+now\s+(a|an|the)\s+`),
	regexp.MustCompile(`(?i)system\s*:\s*you\s+are`),
	regexp.MustCompile(`(?i)forget\s+(everything|all|what)\s+(you|that|i)`),
	regexp.MustCompile(`(?i)new\s+instructions?\s*:`),
	regexp.MustCompile(`(?i)override\s+(your|the|all)\s+(instructions|rules|guidelines)`),
	regexp.MustCompile(`(?i)\bdo\s+anything\s+now\b`),
	regexp.MustCompile(`(?i)(reveal|show|print|repeat|display|output|tell\s+me)\s+(your|the)\s+(system\s+|initial\s+|original\s+)?(prompt|instructions|rules|guidelines)`),
	regexp.MustCompile(`(?i)what\s+(are|were)\s+your\s+(original\s+|initial\s+|system\s+)?(instructions|prompt|rules)`),
	regexp.MustCompile(`(?i)from\s+now\s+on[,\s]+(you|ignore|forget|act|respond|disregard)`),
}

// compactInjectionSignatures are concatenated injection phrases matched against
// the separator-stripped form of text. They catch full-phrase letter-spacing
// ("i g n o r e   a l l   p r e v i o u s") that collapses to a solid string
// no whitespace-aware regex would match.
var compactInjectionSignatures = []string{
	"ignorepreviousinstructions",
	"ignoreallpreviousinstructions",
	"ignorepriorinstructions",
	"ignoreallpriorinstructions",
	"ignoreaboveinstructions",
	"ignoreearlierinstructions",
	"ignorepreviousprompts",
	"ignorepreviousrules",
	"disregardpreviousinstructions",
	"disregardallpreviousinstructions",
	"disregardpriorinstructions",
	"forgetallpreviousinstructions",
	"forgeteverythingabove",
	"revealyoursystemprompt",
	"showyoursystemprompt",
	"printyourinstructions",
	"printyoursystemprompt",
}

func checkPromptInjection(text string) []Violation {
	violations := scanPatterns(text, "prompt_injection", SeverityCritical, injectionPatterns, "Potential prompt injection")
	c := compact(text)
	for _, sig := range compactInjectionSignatures {
		if strings.Contains(c, sig) {
			violations = append(violations, Violation{
				Rule:     "prompt_injection",
				Severity: SeverityCritical,
				Message:  "Potential prompt injection detected (obfuscated: separator/letter-spacing evasion)",
			})
			break
		}
	}
	return violations
}

var jailbreakPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bDAN\s+mode\b`),
	regexp.MustCompile(`(?i)\bjailbreak(en|ing|ed)?\b`),
	regexp.MustCompile(`(?i)developer\s+mode\s+(enabled|on|activated)`),
	regexp.MustCompile(`(?i)(enable|activate|enter)\s+(god|admin|root|sudo|debug)\s+mode`),
	regexp.MustCompile(`(?i)act\s+as\s+an?\s+(unrestricted|unfiltered|uncensored)`),
	regexp.MustCompile(`(?i)pretend\s+(you|that)\s+(have\s+no|don'?t\s+have)\s+(restrictions|limits|rules)`),
	regexp.MustCompile(`(?i)pretend\s+to\s+be\s+an?\s+(unrestricted|unfiltered|uncensored|evil|malicious)`),
	regexp.MustCompile(`(?i)hypothetical(ly)?[^.!?\n]{0,40}(no|without|ignore)\s+(rules|restrictions|filters|guidelines|ethics)`),
}

func checkJailbreak(text string) []Violation {
	return scanPatterns(text, "jailbreak_attempt", SeverityHigh, jailbreakPatterns, "Jailbreak pattern")
}

var sensitiveInputPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(sk-[a-zA-Z0-9_-]{20,})`),
	regexp.MustCompile(`(?i)(ghp_[a-zA-Z0-9]{36,})`),
	regexp.MustCompile(`(?i)(AKIA[0-9A-Z]{16})`),
	regexp.MustCompile(`\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`),
	regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
}

func checkSensitiveDataInput(text string) []Violation {
	st := newScanText(text)
	var violations []Violation
	for _, pat := range sensitiveInputPatterns {
		span, matched, _ := st.find(pat)
		if matched {
			violations = append(violations, Violation{
				Rule:     "sensitive_data_input",
				Severity: SeverityMedium,
				Message:  "Potentially sensitive data detected in prompt input",
				Span:     span,
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
	st := newScanText(text)
	var violations []Violation
	for _, pat := range secretPatterns {
		span, matched, _ := st.find(pat)
		if matched {
			violations = append(violations, Violation{
				Rule:     "secret_leak",
				Severity: SeverityCritical,
				Message:  "Potential secret/credential detected in output",
				Span:     span,
			})
		}
	}
	return violations
}

var harmfulPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)rm\s+-rf\s+/[^a-z]`),
	regexp.MustCompile(`(?i):(){ :\|:& };:`),                                 // fork bomb
	regexp.MustCompile(`(?i)curl\s+[^\s]+\s*\|\s*(?:sudo\s+)?(?:bash|sh)\b`), // pipe to shell
	regexp.MustCompile(`(?i)wget\s+[^\s]+\s*&&\s*(?:sudo\s+)?(?:bash|sh)\b`), // download and execute
}

func checkHarmfulInstruction(text string) []Violation {
	return scanPatterns(text, "harmful_instruction", SeverityHigh, harmfulPatterns, "Potentially harmful instruction")
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
