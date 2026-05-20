package mcp

import (
	"sync"
	"time"
)

// rateLimiter is a sliding-window rate limiter. It bounds how many tool calls
// an MCP client can make within a time window, containing runaway or abusive
// callers without affecting normal use.
type rateLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	events []time.Time
}

// newRateLimiter creates a limiter allowing limit events per window.
// A limit of zero or less disables limiting.
func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{limit: limit, window: window}
}

// allow reports whether an event at time now is within the rate limit. When it
// returns true the event is recorded against the window.
func (r *rateLimiter) allow(now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.limit <= 0 {
		return true
	}

	cutoff := now.Add(-r.window)
	kept := r.events[:0]
	for _, t := range r.events {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	r.events = kept

	if len(r.events) >= r.limit {
		return false
	}
	r.events = append(r.events, now)
	return true
}
