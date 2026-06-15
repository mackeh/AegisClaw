package lineage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTracker_RecordEvent(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "lineage.log")

	tracker, err := NewTracker(path, "exec-001", "test-skill")
	if err != nil {
		t.Fatalf("failed to create tracker: %v", err)
	}
	defer tracker.Close()

	err = tracker.RecordEvent(EventInput, "user", "test-skill", []byte("hello world"), nil)
	if err != nil {
		t.Fatalf("failed to record event: %v", err)
	}

	records, err := ReadAll(path)
	if err != nil {
		t.Fatalf("failed to read records: %v", err)
	}

	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}

	rec := records[0]
	if rec.ExecutionID != "exec-001" {
		t.Errorf("expected execution_id exec-001, got %s", rec.ExecutionID)
	}
	if rec.SkillName != "test-skill" {
		t.Errorf("expected skill_name test-skill, got %s", rec.SkillName)
	}
	if rec.EventType != EventInput {
		t.Errorf("expected event_type input, got %s", rec.EventType)
	}
	if rec.DataHash == "" {
		t.Error("expected data_hash to be set")
	}
	if rec.ByteCount != 11 {
		t.Errorf("expected byte_count 11, got %d", rec.ByteCount)
	}
}

func TestTracker_ConvenienceMethods(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "lineage.log")

	tracker, err := NewTracker(path, "exec-002", "my-skill")
	if err != nil {
		t.Fatalf("failed to create tracker: %v", err)
	}
	defer tracker.Close()

	tracker.RecordInput("cli", []byte("data"))
	tracker.RecordOutput("stdout", []byte("result"))
	tracker.RecordSecretAccess("API_KEY")
	tracker.RecordAPICall("https://api.example.com", 256)

	records, _ := ReadAll(path)
	if len(records) != 4 {
		t.Fatalf("expected 4 records, got %d", len(records))
	}

	expected := []EventType{EventInput, EventOutput, EventSecretRead, EventAPICall}
	for i, rec := range records {
		if rec.EventType != expected[i] {
			t.Errorf("record %d: expected type %s, got %s", i, expected[i], rec.EventType)
		}
	}
}

func TestReadAll_NonexistentFile(t *testing.T) {
	records, err := ReadAll("/nonexistent/lineage.log")
	if err != nil {
		t.Fatalf("expected no error for nonexistent file, got: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("expected 0 records, got %d", len(records))
	}
}

func TestQueryByExecution(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "lineage.log")

	t1, _ := NewTracker(path, "exec-A", "skill-1")
	t1.RecordInput("cli", []byte("a"))
	t1.Close()

	t2, _ := NewTracker(path, "exec-B", "skill-2")
	t2.RecordInput("cli", []byte("b"))
	t2.Close()

	records, err := QueryByExecution(path, "exec-A")
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].ExecutionID != "exec-A" {
		t.Errorf("expected exec-A, got %s", records[0].ExecutionID)
	}
}

func TestQueryBySkill(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "lineage.log")

	t1, _ := NewTracker(path, "exec-1", "alpha")
	t1.RecordInput("cli", []byte("x"))
	t1.RecordOutput("stdout", []byte("y"))
	t1.Close()

	t2, _ := NewTracker(path, "exec-2", "beta")
	t2.RecordInput("cli", []byte("z"))
	t2.Close()

	records, err := QueryBySkill(path, "alpha")
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records for alpha, got %d", len(records))
	}
}

func TestTracker_NilData(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "lineage.log")

	tracker, _ := NewTracker(path, "exec-nil", "skill")
	defer tracker.Close()

	err := tracker.RecordEvent(EventSecretRead, "store", "skill", nil, map[string]any{"key": "val"})
	if err != nil {
		t.Fatalf("recording nil data should succeed: %v", err)
	}

	records, _ := ReadAll(path)
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].DataHash != "" {
		t.Error("expected empty data_hash for nil data")
	}
}

func TestTracker_CreatesDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "nested", "deep", "lineage.log")

	tracker, err := NewTracker(path, "exec-1", "skill")
	if err != nil {
		t.Fatalf("should create nested directories: %v", err)
	}
	tracker.Close()

	if _, err := os.Stat(filepath.Dir(path)); os.IsNotExist(err) {
		t.Fatal("directory was not created")
	}
}
