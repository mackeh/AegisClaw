package profiling

import (
	"testing"
)

func TestLearn_CreatesNewProfile(t *testing.T) {
	dir := t.TempDir()
	p := NewProfiler(dir)

	obs := Observation{
		NetworkTargets: []string{"api.example.com"},
		FileAccess:     []string{"/tmp/data"},
		MemoryMB:       128,
		CPUPercent:     25.0,
	}

	profile, err := p.Learn("test-skill", "1.0.0", obs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if profile.SkillName != "test-skill" {
		t.Errorf("expected skill name 'test-skill', got '%s'", profile.SkillName)
	}
	if profile.SampleCount != 1 {
		t.Errorf("expected sample count 1, got %d", profile.SampleCount)
	}
	if len(profile.NetworkTargets) != 1 {
		t.Errorf("expected 1 network target, got %d", len(profile.NetworkTargets))
	}
	if profile.MaxMemoryMB != 128 {
		t.Errorf("expected max memory 128, got %d", profile.MaxMemoryMB)
	}
}

func TestLearn_MergesObservations(t *testing.T) {
	dir := t.TempDir()
	p := NewProfiler(dir)

	p.Learn("test-skill", "1.0.0", Observation{
		NetworkTargets: []string{"api.example.com"},
		FileAccess:     []string{"/tmp/data"},
		MemoryMB:       128,
	})

	profile, err := p.Learn("test-skill", "1.0.0", Observation{
		NetworkTargets: []string{"api.example.com", "cdn.example.com"},
		FileAccess:     []string{"/tmp/output"},
		MemoryMB:       256,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if profile.SampleCount != 2 {
		t.Errorf("expected sample count 2, got %d", profile.SampleCount)
	}
	if len(profile.NetworkTargets) != 2 {
		t.Errorf("expected 2 network targets, got %d", len(profile.NetworkTargets))
	}
	if len(profile.FileAccess) != 2 {
		t.Errorf("expected 2 file access entries, got %d", len(profile.FileAccess))
	}
	if profile.MaxMemoryMB != 256 {
		t.Errorf("expected max memory 256, got %d", profile.MaxMemoryMB)
	}
}

func TestCheck_NoProfile(t *testing.T) {
	dir := t.TempDir()
	p := NewProfiler(dir)

	anomalies, err := p.Check("nonexistent", Observation{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if anomalies != nil {
		t.Error("expected nil anomalies for missing profile")
	}
}

func TestCheck_DetectsNewNetworkTarget(t *testing.T) {
	dir := t.TempDir()
	p := NewProfiler(dir)

	p.Learn("test-skill", "1.0.0", Observation{
		NetworkTargets: []string{"api.example.com"},
		MemoryMB:       128,
	})

	anomalies, err := p.Check("test-skill", Observation{
		NetworkTargets: []string{"api.example.com", "evil.com"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(anomalies) != 1 {
		t.Fatalf("expected 1 anomaly, got %d", len(anomalies))
	}
	if anomalies[0].Type != "network" {
		t.Errorf("expected network anomaly, got %s", anomalies[0].Type)
	}
	if anomalies[0].Severity != "high" {
		t.Errorf("expected high severity, got %s", anomalies[0].Severity)
	}
}

func TestCheck_DetectsMemoryAnomaly(t *testing.T) {
	dir := t.TempDir()
	p := NewProfiler(dir)

	p.Learn("test-skill", "1.0.0", Observation{
		MemoryMB: 100,
	})

	anomalies, err := p.Check("test-skill", Observation{
		MemoryMB: 200, // > 150 (100 * 1.5)
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, a := range anomalies {
		if a.Type == "memory" {
			found = true
		}
	}
	if !found {
		t.Error("expected memory anomaly")
	}
}

func TestCheck_NoAnomalyWithinThreshold(t *testing.T) {
	dir := t.TempDir()
	p := NewProfiler(dir)

	p.Learn("test-skill", "1.0.0", Observation{
		NetworkTargets: []string{"api.example.com"},
		FileAccess:     []string{"/tmp/data"},
		MemoryMB:       100,
		CPUPercent:     20.0,
	})

	anomalies, err := p.Check("test-skill", Observation{
		NetworkTargets: []string{"api.example.com"},
		FileAccess:     []string{"/tmp/data"},
		MemoryMB:       120, // within 1.5x threshold
		CPUPercent:     25.0,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(anomalies) != 0 {
		t.Errorf("expected 0 anomalies, got %d: %+v", len(anomalies), anomalies)
	}
}

func TestListProfiles(t *testing.T) {
	dir := t.TempDir()
	p := NewProfiler(dir)

	p.Learn("skill-a", "1.0", Observation{})
	p.Learn("skill-b", "2.0", Observation{})

	names, err := p.ListProfiles()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(names) != 2 {
		t.Errorf("expected 2 profiles, got %d", len(names))
	}
}

func TestDelete(t *testing.T) {
	dir := t.TempDir()
	p := NewProfiler(dir)

	p.Learn("test-skill", "1.0", Observation{})

	err := p.Delete("test-skill")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	profile, _ := p.Load("test-skill")
	if profile != nil {
		t.Error("profile should be deleted")
	}
}
