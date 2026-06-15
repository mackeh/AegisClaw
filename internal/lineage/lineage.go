// Package lineage tracks data provenance through agent skill executions.
// It records inputs, outputs, secrets accessed, and external APIs called
// for each execution, enabling data governance and regulatory compliance.
package lineage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// EventType classifies the kind of data flow event.
type EventType string

const (
	EventInput      EventType = "input"       // Data entering the skill
	EventOutput     EventType = "output"      // Data produced by the skill
	EventSecretRead EventType = "secret_read" // Secret accessed during execution
	EventAPICall    EventType = "api_call"    // External API invocation
	EventFileRead   EventType = "file_read"   // File read inside sandbox
	EventFileWrite  EventType = "file_write"  // File written inside sandbox
)

// Record represents a single data flow event in a skill execution.
type Record struct {
	Timestamp   time.Time      `json:"timestamp"`
	ExecutionID string         `json:"execution_id"`
	SkillName   string         `json:"skill_name"`
	EventType   EventType      `json:"event_type"`
	Source      string         `json:"source"`              // Where data came from
	Destination string         `json:"destination"`         // Where data went
	DataHash    string         `json:"data_hash,omitempty"` // SHA256 of the data (not the data itself)
	ByteCount   int64          `json:"byte_count,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// Tracker records data lineage events for a skill execution.
type Tracker struct {
	mu          sync.Mutex
	file        *os.File
	executionID string
	skillName   string
}

// NewTracker creates a lineage tracker for a specific execution.
func NewTracker(lineagePath, executionID, skillName string) (*Tracker, error) {
	dir := filepath.Dir(lineagePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create lineage directory: %w", err)
	}

	file, err := os.OpenFile(lineagePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open lineage log: %w", err)
	}

	return &Tracker{
		file:        file,
		executionID: executionID,
		skillName:   skillName,
	}, nil
}

// RecordEvent logs a data flow event.
func (t *Tracker) RecordEvent(eventType EventType, source, destination string, data []byte, metadata map[string]any) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	record := Record{
		Timestamp:   time.Now().UTC(),
		ExecutionID: t.executionID,
		SkillName:   t.skillName,
		EventType:   eventType,
		Source:      source,
		Destination: destination,
		Metadata:    metadata,
	}

	if len(data) > 0 {
		hash := sha256.Sum256(data)
		record.DataHash = hex.EncodeToString(hash[:])
		record.ByteCount = int64(len(data))
	}

	line, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal lineage record: %w", err)
	}

	if _, err := t.file.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("failed to write lineage record: %w", err)
	}

	return t.file.Sync()
}

// RecordInput is a convenience method for recording skill input.
func (t *Tracker) RecordInput(source string, data []byte) error {
	return t.RecordEvent(EventInput, source, t.skillName, data, nil)
}

// RecordOutput is a convenience method for recording skill output.
func (t *Tracker) RecordOutput(destination string, data []byte) error {
	return t.RecordEvent(EventOutput, t.skillName, destination, data, nil)
}

// RecordSecretAccess records that a secret was read during execution.
func (t *Tracker) RecordSecretAccess(secretName string) error {
	return t.RecordEvent(EventSecretRead, "secrets_store", t.skillName, nil, map[string]any{
		"secret_name": secretName,
	})
}

// RecordAPICall records an external API invocation.
func (t *Tracker) RecordAPICall(endpoint string, bytesSent int64) error {
	return t.RecordEvent(EventAPICall, t.skillName, endpoint, nil, map[string]any{
		"bytes_sent": bytesSent,
	})
}

// Close closes the lineage log file.
func (t *Tracker) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.file.Close()
}

// ReadAll reads all lineage records from a log file.
func ReadAll(path string) ([]Record, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []Record{}, nil
		}
		return nil, fmt.Errorf("failed to read lineage log: %w", err)
	}

	var records []Record
	start := 0
	for i, b := range data {
		if b == '\n' {
			if i > start {
				var rec Record
				if err := json.Unmarshal(data[start:i], &rec); err == nil {
					records = append(records, rec)
				}
			}
			start = i + 1
		}
	}
	if start < len(data) {
		var rec Record
		if err := json.Unmarshal(data[start:], &rec); err == nil {
			records = append(records, rec)
		}
	}

	return records, nil
}

// QueryByExecution returns all lineage records for a specific execution ID.
func QueryByExecution(path, executionID string) ([]Record, error) {
	all, err := ReadAll(path)
	if err != nil {
		return nil, err
	}

	var filtered []Record
	for _, r := range all {
		if r.ExecutionID == executionID {
			filtered = append(filtered, r)
		}
	}
	return filtered, nil
}

// QueryBySkill returns all lineage records for a specific skill.
func QueryBySkill(path, skillName string) ([]Record, error) {
	all, err := ReadAll(path)
	if err != nil {
		return nil, err
	}

	var filtered []Record
	for _, r := range all {
		if r.SkillName == skillName {
			filtered = append(filtered, r)
		}
	}
	return filtered, nil
}
