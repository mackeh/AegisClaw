package guardrails

import "regexp"

// defaultDataRules detect indirect prompt injection — instructions embedded in
// untrusted content the agent reads (web pages, tool outputs, files) rather
// than typed by the user. The classic direct-injection and jailbreak rules are
// reused because injected data often carries the same payloads.
func defaultDataRules() []Rule {
	return []Rule{
		{Name: "indirect_injection", Severity: SeverityCritical, CheckFn: checkIndirectInjection},
		{Name: "embedded_directive", Severity: SeverityHigh, CheckFn: checkEmbeddedDirective},
		{Name: "prompt_injection", Severity: SeverityCritical, CheckFn: checkPromptInjection},
		{Name: "jailbreak_attempt", Severity: SeverityHigh, CheckFn: checkJailbreak},
	}
}

// indirectInjectionPatterns flag content that addresses the AI directly or
// forges conversation delimiters to impersonate a trusted role.
var indirectInjectionPatterns = []*regexp.Regexp{
	// Content that names the AI and tells it to override its instructions.
	regexp.MustCompile(`(?i)\b(ai|assistant|llm|chatbot|language\s+model)\b[^.!?\n]{0,50}\b(ignore|disregard|forget|override)\s+(your|all|the|previous|prior|these|any|earlier)\b`),
	// "if you are an AI / reading this" framing.
	regexp.MustCompile(`(?i)\b(if|when)\s+you\s+(are\s+)?(an?\s+)?(ai|assistant|agent|language\s+model|reading\s+this|an\s+llm)`),
	// Notes explicitly addressed to an AI reader.
	regexp.MustCompile(`(?i)\b(attention|important|note|notice|warning|message)\b\s*[:,\-]*\s*(to|for)\s+(the\s+)?(ai|assistant|agent|model|llm|reader|whoever\s+is\s+reading)`),
	// Forged conversation/role delimiters.
	regexp.MustCompile(`(?i)<\s*/?\s*(system|assistant|user|tool|function|context)\s*>`),
	regexp.MustCompile(`(?i)\[\s*/?\s*(system|assistant|inst)\s*\]`),
	regexp.MustCompile(`(?i)<\|?\s*(im_start|im_end|system|endoftext)\s*\|?>`),
	regexp.MustCompile(`(?i)<<\s*/?\s*sys\s*>>`),
	regexp.MustCompile(`(?i)#{2,}\s*(system\s+prompt|system\s+instruction|new\s+instructions?|new\s+task)`),
}

// embeddedDirectivePatterns flag imperative directives hidden inside data —
// instructions buried in HTML comments, commands to act behind the user's
// back, or directives to exfiltrate information.
var embeddedDirectivePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?is)<!--[^>]*\b(ignore|instruction|system\s+prompt|do\s+not|you\s+must|assistant|prompt)\b[^>]*-->`),
	regexp.MustCompile(`(?i)(do\s+not|don'?t|never)\s+(tell|inform|mention\s+to|reveal\s+to|notify|alert)\s+the\s+user`),
	regexp.MustCompile(`(?i)without\s+(telling|informing|asking|notifying|alerting)\s+the\s+user`),
	regexp.MustCompile(`(?i)(send|exfiltrate|post|upload|email|leak|forward|transmit)\s+(?:(?:the|all|your|its|user'?s?)\s+){0,3}(data|contents?|files?|credentials?|secrets?|passwords?|keys?|tokens?|information|conversation|history|logs?)\b[^.\n]{0,30}\b(to|at)\s+https?://`),
}

func checkIndirectInjection(text string) []Violation {
	return scanPatterns(text, "indirect_injection", SeverityCritical, indirectInjectionPatterns, "Indirect prompt injection")
}

func checkEmbeddedDirective(text string) []Violation {
	return scanPatterns(text, "embedded_directive", SeverityHigh, embeddedDirectivePatterns, "Embedded directive in untrusted data")
}
