// Package profiling implements runtime behaviour profiling for skills.
// In learning mode, it captures network targets, file access patterns,
// and resource usage. In enforcement mode, it flags anomalies.
package profiling

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Profile represents the learned behaviour baseline for a skill.
type Profile struct {
	SkillName      string            `json:"skill_name"`
	Version        string            `json:"version"`
	NetworkTargets []string          `json:"network_targets"`
	FileAccess     []string          `json:"file_access"`
	MaxMemoryMB    int               `json:"max_memory_mb"`
	MaxCPUPercent  float64           `json:"max_cpu_percent"`
	SampleCount    int               `json:"sample_count"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

// Observation captures behaviour from a single skill run.
type Observation struct {
	NetworkTargets []string `json:"network_targets"`
	FileAccess     []string `json:"file_access"`
	MemoryMB       int      `json:"memory_mb"`
	CPUPercent     float64  `json:"cpu_percent"`
	Duration       time.Duration `json:"duration"`
}

// Anomaly represents a deviation from the learned profile.
type Anomaly struct {
	Type    string `json:"type"`    // "network", "file", "memory", "cpu"
	Detail  string `json:"detail"`
	Severity string `json:"severity"` // "low", "medium", "high"
}

// Profiler manages skill behaviour profiles.
type Profiler struct {
	profileDir string
}

// NewProfiler creates a profiler that stores profiles in the given directory.
func NewProfiler(profileDir string) *Profiler {
	os.MkdirAll(profileDir, 0700)
	return &Profiler{profileDir: profileDir}
}

// Load reads a profile for the given skill. Returns nil if no profile exists.
func (p *Profiler) Load(skillName string) (*Profile, error) {
	path := p.profilePath(skillName)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read profile: %w", err)
	}

	var profile Profile
	if err := json.Unmarshal(data, &profile); err != nil {
		return nil, fmt.Errorf("failed to parse profile: %w", err)
	}
	return &profile, nil
}

// Save writes a profile to disk.
func (p *Profiler) Save(profile *Profile) error {
	profile.UpdatedAt = time.Now().UTC()
	data, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal profile: %w", err)
	}
	return os.WriteFile(p.profilePath(profile.SkillName), data, 0600)
}

// Learn incorporates a new observation into an existing profile.
// If no profile exists, creates one from the observation.
func (p *Profiler) Learn(skillName, version string, obs Observation) (*Profile, error) {
	profile, err := p.Load(skillName)
	if err != nil {
		return nil, err
	}

	if profile == nil {
		profile = &Profile{
			SkillName: skillName,
			Version:   version,
			CreatedAt: time.Now().UTC(),
		}
	}

	// Merge network targets
	profile.NetworkTargets = mergeUnique(profile.NetworkTargets, obs.NetworkTargets)

	// Merge file access
	profile.FileAccess = mergeUnique(profile.FileAccess, obs.FileAccess)

	// Update resource high-water marks
	if obs.MemoryMB > profile.MaxMemoryMB {
		profile.MaxMemoryMB = obs.MemoryMB
	}
	if obs.CPUPercent > profile.MaxCPUPercent {
		profile.MaxCPUPercent = obs.CPUPercent
	}

	profile.SampleCount++

	if err := p.Save(profile); err != nil {
		return nil, err
	}
	return profile, nil
}

// Check compares an observation against the learned profile and returns anomalies.
func (p *Profiler) Check(skillName string, obs Observation) ([]Anomaly, error) {
	profile, err := p.Load(skillName)
	if err != nil {
		return nil, err
	}
	if profile == nil {
		return nil, nil // No profile = no enforcement
	}

	var anomalies []Anomaly

	// Check for new network targets
	known := toSet(profile.NetworkTargets)
	for _, target := range obs.NetworkTargets {
		if !known[target] {
			anomalies = append(anomalies, Anomaly{
				Type:     "network",
				Detail:   fmt.Sprintf("unexpected network target: %s", target),
				Severity: "high",
			})
		}
	}

	// Check for new file access
	knownFiles := toSet(profile.FileAccess)
	for _, path := range obs.FileAccess {
		if !knownFiles[path] {
			anomalies = append(anomalies, Anomaly{
				Type:     "file",
				Detail:   fmt.Sprintf("unexpected file access: %s", path),
				Severity: "medium",
			})
		}
	}

	// Check memory (allow 50% headroom over learned max)
	memoryThreshold := int(float64(profile.MaxMemoryMB) * 1.5)
	if memoryThreshold < 64 {
		memoryThreshold = 64
	}
	if obs.MemoryMB > memoryThreshold {
		anomalies = append(anomalies, Anomaly{
			Type:     "memory",
			Detail:   fmt.Sprintf("memory usage %dMB exceeds threshold %dMB", obs.MemoryMB, memoryThreshold),
			Severity: "medium",
		})
	}

	// Check CPU (allow 50% headroom)
	cpuThreshold := profile.MaxCPUPercent * 1.5
	if cpuThreshold < 10 {
		cpuThreshold = 10
	}
	if obs.CPUPercent > cpuThreshold {
		anomalies = append(anomalies, Anomaly{
			Type:     "cpu",
			Detail:   fmt.Sprintf("CPU usage %.1f%% exceeds threshold %.1f%%", obs.CPUPercent, cpuThreshold),
			Severity: "low",
		})
	}

	return anomalies, nil
}

// Delete removes a skill profile.
func (p *Profiler) Delete(skillName string) error {
	path := p.profilePath(skillName)
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// ListProfiles returns the names of all profiled skills.
func (p *Profiler) ListProfiles() ([]string, error) {
	entries, err := os.ReadDir(p.profileDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var names []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			name := e.Name()
			names = append(names, name[:len(name)-5]) // strip .json
		}
	}
	return names, nil
}

func (p *Profiler) profilePath(skillName string) string {
	return filepath.Join(p.profileDir, skillName+".json")
}

func mergeUnique(existing, incoming []string) []string {
	set := toSet(existing)
	for _, item := range incoming {
		if !set[item] {
			existing = append(existing, item)
			set[item] = true
		}
	}
	return existing
}

func toSet(items []string) map[string]bool {
	s := make(map[string]bool, len(items))
	for _, item := range items {
		s[item] = true
	}
	return s
}
