package mcp

import (
	"testing"
	"time"
)

func TestRateLimiterAllowsUpToLimit(t *testing.T) {
	rl := newRateLimiter(3, time.Minute)
	now := time.Now()
	for i := 0; i < 3; i++ {
		if !rl.allow(now) {
			t.Fatalf("call %d should be allowed", i+1)
		}
	}
	if rl.allow(now) {
		t.Error("4th call should be denied")
	}
}

func TestRateLimiterWindowExpiry(t *testing.T) {
	rl := newRateLimiter(2, time.Minute)
	base := time.Now()
	if !rl.allow(base) || !rl.allow(base) {
		t.Fatal("first two calls should be allowed")
	}
	if rl.allow(base) {
		t.Fatal("third call within the window should be denied")
	}
	later := base.Add(2 * time.Minute)
	if !rl.allow(later) {
		t.Error("call after the window slides past should be allowed again")
	}
}

func TestRateLimiterDisabled(t *testing.T) {
	rl := newRateLimiter(0, time.Minute)
	now := time.Now()
	for i := 0; i < 1000; i++ {
		if !rl.allow(now) {
			t.Fatal("a limiter with limit <= 0 should allow everything")
		}
	}
}
