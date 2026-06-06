package redactor

import (
	"io"
	"strings"
	"sync"
)

// Redactor handles the scrubbing of sensitive information from text
type Redactor struct {
	mu      sync.RWMutex
	secrets []string
}

// New creates a new Redactor with an initial list of secrets
func New(secrets ...string) *Redactor {
	r := &Redactor{}
	for _, s := range secrets {
		if len(s) > 4 { // Only redact secrets longer than 4 chars to avoid false positives on common words
			r.secrets = append(r.secrets, s)
		}
	}
	return r
}

// Add adds a secret to the redaction list
func (r *Redactor) Add(secret string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(secret) > 4 {
		r.secrets = append(r.secrets, secret)
	}
}

// Redact replaces all known secrets in the input string with [REDACTED]
func (r *Redactor) Redact(input string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if len(r.secrets) == 0 {
		return input
	}

	result := input
	for _, secret := range r.secrets {
		if strings.Contains(result, secret) {
			result = strings.ReplaceAll(result, secret, "[REDACTED]")
		}
	}
	return result
}

// RedactingWriter wraps an io.Writer and redact secrets before writing
type RedactingWriter struct {
	writer   io.Writer
	redactor *Redactor
}

// NewRedactingWriter creates a new writer that scrubs output
func NewRedactingWriter(w io.Writer, r *Redactor) *RedactingWriter {
	return &RedactingWriter{
		writer:   w,
		redactor: r,
	}
}

func (w *RedactingWriter) Write(p []byte) (n int, err error) {
	// Simple approach: convert to string, redact, write.
	// Note: This may split multi-byte characters or secrets across chunk boundaries if not careful.
	// For a robust implementation, we'd need a buffer, but for MVP this catches most "cat secrets.txt" cases.
	
	s := string(p)
	redacted := w.redactor.Redact(s)
	
	// If redaction happened, the length changed, which breaks the io.Writer contract if we return the new length.
	// We must return len(p) to satisfy the caller, even if we wrote fewer/more bytes underlying.
	
	_, err = w.writer.Write([]byte(redacted))
	return len(p), err
}
