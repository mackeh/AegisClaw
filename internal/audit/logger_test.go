package audit

import (
	"path/filepath"
	"testing"

	"github.com/mackeh/AegisClaw/internal/scope"
)

func TestNewLogger(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit", "audit.log")

	logger, err := NewLogger(logPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer logger.Close()

	if logger.lastHash != "genesis" {
		t.Errorf("expected genesis hash, got %s", logger.lastHash)
	}
}

func TestLogger_Log(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	logger, err := NewLogger(logPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = logger.Log("test_action", []scope.Scope{{Name: "files.read", Resource: "/tmp"}}, "allow", "test-user", nil)
	if err != nil {
		t.Fatalf("log error: %v", err)
	}

	if logger.lastHash == "genesis" {
		t.Error("lastHash should have changed after logging")
	}
	logger.Close()

	// Verify the entry was written
	entries, err := ReadAll(logPath)
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Action != "test_action" {
		t.Errorf("expected action 'test_action', got '%s'", entries[0].Action)
	}
	if entries[0].Decision != "allow" {
		t.Errorf("expected decision 'allow', got '%s'", entries[0].Decision)
	}
}

func TestLogger_HashChain(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	logger, err := NewLogger(logPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	logger.Log("action1", nil, "allow", "user1", nil)
	hash1 := logger.lastHash

	logger.Log("action2", nil, "deny", "user2", nil)
	hash2 := logger.lastHash

	if hash1 == hash2 {
		t.Error("consecutive entries should have different hashes")
	}
	logger.Close()

	// Verify chain integrity
	valid, err := Verify(logPath)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if !valid {
		t.Error("expected valid chain")
	}
}

func TestReadAll_NonExistent(t *testing.T) {
	entries, err := ReadAll("/nonexistent/path/audit.log")
	if err != nil {
		t.Fatalf("expected nil error for missing file, got: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestVerify_Empty(t *testing.T) {
	valid, err := Verify("/nonexistent/path/audit.log")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !valid {
		t.Error("empty/missing log should verify as valid")
	}
}

func TestVerify_ValidChain(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	logger, err := NewLogger(logPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for i := 0; i < 10; i++ {
		logger.Log("action", nil, "allow", "user", nil)
	}
	logger.Close()

	valid, err := Verify(logPath)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if !valid {
		t.Error("expected valid chain for 10 entries")
	}
}

func TestLogger_ResumeChain(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	// Write initial entries
	logger1, _ := NewLogger(logPath)
	logger1.Log("action1", nil, "allow", "user", nil)
	logger1.Log("action2", nil, "deny", "user", nil)
	lastHash := logger1.lastHash
	logger1.Close()

	// Reopen and continue
	logger2, _ := NewLogger(logPath)
	if logger2.lastHash != lastHash {
		t.Error("expected logger to resume from last hash")
	}
	logger2.Log("action3", nil, "allow", "user", nil)
	logger2.Close()

	// Verify full chain
	valid, err := Verify(logPath)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if !valid {
		t.Error("expected valid chain across logger restarts")
	}

	entries, _ := ReadAll(logPath)
	if len(entries) != 3 {
		t.Errorf("expected 3 entries, got %d", len(entries))
	}
}
