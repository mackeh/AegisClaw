package llmproxy

import (
	"testing"
	"time"
)

func TestExtractPromptProviderAgnostic(t *testing.T) {
	openai := []byte(`{"model":"gpt-4o","messages":[{"role":"system","content":"be nice"},{"role":"user","content":"hello"}]}`)
	if got := extractPrompt(openai); got == "" || !contains(got, "be nice") || !contains(got, "hello") {
		t.Fatalf("openai prompt extraction failed: %q", got)
	}

	// Anthropic: top-level system + array content parts.
	anthropic := []byte(`{"model":"claude-sonnet","system":"sys","messages":[{"role":"user","content":[{"type":"text","text":"world"}]}]}`)
	if got := extractPrompt(anthropic); !contains(got, "sys") || !contains(got, "world") {
		t.Fatalf("anthropic prompt extraction failed: %q", got)
	}
}

func TestExtractUsageBothProviders(t *testing.T) {
	if u := extractUsage([]byte(`{"usage":{"prompt_tokens":7,"completion_tokens":3}}`)); u.InputTokens != 7 || u.OutputTokens != 3 {
		t.Fatalf("openai usage: %+v", u)
	}
	if u := extractUsage([]byte(`{"usage":{"input_tokens":9,"output_tokens":4}}`)); u.InputTokens != 9 || u.OutputTokens != 4 {
		t.Fatalf("anthropic usage: %+v", u)
	}
}

func TestPricingLongestMatchWins(t *testing.T) {
	// "gpt-4o" must beat the shorter "gpt-4" prefix.
	if got := priceFor("gpt-4o"); got.InputPer1M != 2.50 {
		t.Fatalf("gpt-4o pricing = %+v", got)
	}
	if got := priceFor("totally-unknown-model"); got != (Pricing{}) {
		t.Fatalf("unknown model should have zero pricing, got %+v", got)
	}
}

func TestBudgetLimits(t *testing.T) {
	b := &Budget{MaxTokens: 100}
	if err := b.Check(); err != nil {
		t.Fatalf("fresh budget should pass: %v", err)
	}
	b.AddUsage(60, 50, 0) // 110 tokens, over the 100 cap
	if err := b.Check(); err == nil {
		t.Fatal("expected token budget to be exhausted")
	}
}

func TestLoopGuardWindow(t *testing.T) {
	lg := newLoopGuard(2, time.Minute)
	now := time.Now()
	if _, tripped := lg.record([]byte("x"), now); tripped {
		t.Fatal("first occurrence should not trip")
	}
	if _, tripped := lg.record([]byte("x"), now); !tripped {
		t.Fatal("second occurrence should trip threshold of 2")
	}
	// A different body is tracked independently.
	if _, tripped := lg.record([]byte("y"), now); tripped {
		t.Fatal("distinct body should not trip")
	}
}

func contains(s, sub string) bool { return len(s) >= len(sub) && (indexOf(s, sub) >= 0) }
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
