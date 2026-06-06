package llmproxy

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// loopGuard detects runaway agentic loops: the same request body repeated many
// times in a short window, which is the signature of a self-prompting agent
// stuck in a cycle. A threshold of zero disables detection.
type loopGuard struct {
	mu        sync.Mutex
	threshold int
	window    time.Duration
	seen      map[string][]time.Time
}

func newLoopGuard(threshold int, window time.Duration) *loopGuard {
	return &loopGuard{threshold: threshold, window: window, seen: make(map[string][]time.Time)}
}

func fingerprint(body []byte) string {
	h := sha256.Sum256(body)
	return hex.EncodeToString(h[:])
}

// record registers a request fingerprint at time now and reports how many times
// it has occurred within the window and whether that trips the loop threshold.
func (l *loopGuard) record(body []byte, now time.Time) (count int, tripped bool) {
	if l == nil || l.threshold <= 0 {
		return 0, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	fp := fingerprint(body)
	cutoff := now.Add(-l.window)
	kept := l.seen[fp][:0]
	for _, t := range l.seen[fp] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	l.seen[fp] = kept

	return len(kept), len(kept) >= l.threshold
}
