package llmproxy

import (
	"fmt"
	"strings"
	"sync"
	"unicode/utf8"
)

// Pricing is the approximate USD cost per 1M input/output tokens for a model
// family. Values are coarse and used only for budget enforcement, not billing.
type Pricing struct {
	InputPer1M  float64
	OutputPer1M float64
}

// defaultPricing maps a model-name substring to its pricing. The longest
// matching key wins so "gpt-4o" beats "gpt-4".
var defaultPricing = map[string]Pricing{
	"gpt-4o-mini":       {0.15, 0.60},
	"gpt-4o":            {2.50, 10.00},
	"gpt-4":             {30.00, 60.00},
	"gpt-3.5":           {0.50, 1.50},
	"o1":                {15.00, 60.00},
	"claude-3-5-haiku":  {0.80, 4.00},
	"claude-haiku":      {0.80, 4.00},
	"claude-3-5-sonnet": {3.00, 15.00},
	"claude-sonnet":     {3.00, 15.00},
	"claude-3-opus":     {15.00, 75.00},
	"claude-opus":       {15.00, 75.00},
}

// priceFor returns the pricing for a model, or zero if unknown.
func priceFor(model string) Pricing {
	model = strings.ToLower(model)
	best := ""
	for key := range defaultPricing {
		if strings.Contains(model, key) && len(key) > len(best) {
			best = key
		}
	}
	if best == "" {
		return Pricing{}
	}
	return defaultPricing[best]
}

// cost computes the USD cost of a call given input/output token counts.
func (p Pricing) cost(inTokens, outTokens int) float64 {
	return float64(inTokens)/1e6*p.InputPer1M + float64(outTokens)/1e6*p.OutputPer1M
}

// estimateTokens approximates a token count from text length (~4 chars/token).
// Used when the provider does not report usage (e.g. streaming responses).
func estimateTokens(text string) int {
	return utf8.RuneCountInString(text)/4 + 1
}

// Budget enforces per-session caps on tokens, cost, and request count for a
// single agent session. A limit of zero means unlimited. It is safe for
// concurrent use.
type Budget struct {
	MaxTokens   int
	MaxCostUSD  float64
	MaxRequests int

	mu       sync.Mutex
	tokens   int
	cost     float64
	requests int
}

// Check reports whether a new request is permitted under the current totals.
func (b *Budget) Check() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.MaxRequests > 0 && b.requests >= b.MaxRequests {
		return fmt.Errorf("request budget exhausted (%d/%d)", b.requests, b.MaxRequests)
	}
	if b.MaxTokens > 0 && b.tokens >= b.MaxTokens {
		return fmt.Errorf("token budget exhausted (%d/%d)", b.tokens, b.MaxTokens)
	}
	if b.MaxCostUSD > 0 && b.cost >= b.MaxCostUSD {
		return fmt.Errorf("cost budget exhausted ($%.4f/$%.4f)", b.cost, b.MaxCostUSD)
	}
	return nil
}

// AddRequest increments the request counter.
func (b *Budget) AddRequest() {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.requests++
	b.mu.Unlock()
}

// AddUsage records tokens and cost consumed by a completed call.
func (b *Budget) AddUsage(inTokens, outTokens int, cost float64) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.tokens += inTokens + outTokens
	b.cost += cost
	b.mu.Unlock()
}

// Snapshot returns the current totals.
func (b *Budget) Snapshot() (tokens int, cost float64, requests int) {
	if b == nil {
		return 0, 0, 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.tokens, b.cost, b.requests
}
