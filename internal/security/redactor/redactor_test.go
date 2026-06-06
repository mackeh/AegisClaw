package redactor

import (
	"bytes"
	"testing"
)

func TestRedact(t *testing.T) {
	r := New("secret123", "password456")
	
	input := "This is a secret123 and another password456."
	expected := "This is a [REDACTED] and another [REDACTED]."
	
	got := r.Redact(input)
	if got != expected {
		t.Errorf("Redact() = %q, want %q", got, expected)
	}
}

func TestRedactingWriter(t *testing.T) {
	r := New("hidden")
	var buf bytes.Buffer
	w := NewRedactingWriter(&buf, r)
	
	input := "This is hidden content."
	expected := "This is [REDACTED] content."
	
	n, err := w.Write([]byte(input))
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	
	if n != len(input) {
		t.Errorf("Write returned %d, want %d", n, len(input))
	}
	
	if buf.String() != expected {
		t.Errorf("Buffer = %q, want %q", buf.String(), expected)
	}
}
