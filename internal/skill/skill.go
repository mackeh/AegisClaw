package skill

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Manifest represents a skill definition (skill.yaml)
type Manifest struct {
	Name        string            `yaml:"name"`
	Version     string            `yaml:"version"`
	Description string            `yaml:"description"`
	Image       string            `yaml:"image"`
	Scopes      []string          `yaml:"scopes"`
	Commands    map[string]Command `yaml:"commands"`
}

// Command represents a runnable action within a skill
type Command struct {
	Args []string `yaml:"args"`
	Env  []string `yaml:"env,omitempty"`
}

// LoadManifest reads and verifies a skill manifest
func LoadManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read skill manifest: %w", err)
	}

	var m Manifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("failed to parse skill manifest: %w", err)
	}

	if m.Name == "" || m.Image == "" {
		return nil, fmt.Errorf("invalid manifest: name and image are required")
	}

	return &m, nil
}
