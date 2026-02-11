package skill

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Manifest represents a skill definition (skill.yaml)
type Manifest struct {
	Name        string             `yaml:"name"`
	Version     string             `yaml:"version"`
	Description string             `yaml:"description"`
	Image       string             `yaml:"image"`
	Platform    string             `yaml:"platform,omitempty"`      // "docker" (default) or "docker-compose"
	ComposeFile string             `yaml:"compose_file,omitempty"`  // path to docker-compose.yml (relative to manifest)
	Scopes      []string           `yaml:"scopes"`
	Services    map[string]Service `yaml:"services,omitempty"`      // per-service scope declarations for compose
	Commands    map[string]Command `yaml:"commands"`
	Signature   string             `yaml:"signature,omitempty"`     // Ed25519 signature of the manifest content
}

// Service describes per-service configuration in a compose skill.
type Service struct {
	Scopes []string `yaml:"scopes"`
}

// IsCompose returns true if this skill uses docker-compose.
func (m *Manifest) IsCompose() bool {
	return m.Platform == "docker-compose"
}

// RegistrySkill represents a skill available in the registry
type RegistrySkill struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
	ManifestURL string `json:"manifest_url"`
}

// RegistryIndex represents the registry search index
type RegistryIndex struct {
	RegistryName string          `json:"registry_name"`
	Skills       []RegistrySkill `json:"skills"`
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

	if m.Name == "" {
		return nil, fmt.Errorf("invalid manifest: name is required")
	}
	if m.Image == "" && !m.IsCompose() {
		return nil, fmt.Errorf("invalid manifest: image is required for non-compose skills")
	}
	if m.IsCompose() && m.ComposeFile == "" {
		return nil, fmt.Errorf("invalid manifest: compose_file is required for docker-compose skills")
	}

	return &m, nil
}

// ListSkills scans the given directory for skill manifests
func ListSkills(dir string) ([]*Manifest, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read skills directory: %w", err)
	}

	var manifests []*Manifest
	for _, entry := range entries {
		if entry.IsDir() {
			manifestPath := filepath.Join(dir, entry.Name(), "skill.yaml")
			if _, err := os.Stat(manifestPath); err == nil {
				m, err := LoadManifest(manifestPath)
				if err == nil {
					manifests = append(manifests, m)
				}
			}
		}
	}
	return manifests, nil
}

// VerifySignature validates the manifest signature using a list of trusted public keys
func (m *Manifest) VerifySignature(trustKeys []string) (bool, error) {
	if m.Signature == "" {
		return false, fmt.Errorf("manifest has no signature")
	}

	sigBytes, err := hex.DecodeString(m.Signature)
	if err != nil {
		return false, fmt.Errorf("invalid signature hex: %w", err)
	}

	// Create a copy without the signature for hashing/verification
	mCopy := *m
	mCopy.Signature = ""

	// Canonical JSON serialization for hashing
	data, err := json.Marshal(mCopy)
	if err != nil {
		return false, fmt.Errorf("failed to marshal manifest for verification: %w", err)
	}

	for _, keyStr := range trustKeys {
		pubKeyBytes, err := hex.DecodeString(keyStr)
		if err != nil {
			continue // Skip invalid keys
		}

		if len(pubKeyBytes) != ed25519.PublicKeySize {
			continue
		}

		pubKey := ed25519.PublicKey(pubKeyBytes)
		if ed25519.Verify(pubKey, data, sigBytes) {
			return true, nil
		}
	}

	return false, nil
}

// SearchRegistry fetches the registry index
func SearchRegistry(registryURL string) (*RegistryIndex, error) {
	resp, err := http.Get(registryURL + "/index.json")
	if err != nil {
		return nil, fmt.Errorf("failed to fetch registry index: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry returned error: %s", resp.Status)
	}

	var index RegistryIndex
	if err := json.NewDecoder(resp.Body).Decode(&index); err != nil {
		return nil, fmt.Errorf("failed to decode registry index: %w", err)
	}

	return &index, nil
}

// InstallSkill downloads and installs a skill from the registry
func InstallSkill(skillName, destDir, registryURL string, trustKeys []string) error {
	index, err := SearchRegistry(registryURL)
	if err != nil {
		return err
	}

	var target *RegistrySkill
	for _, s := range index.Skills {
		if s.Name == skillName {
			target = &s
			break
		}
	}

	if target == nil {
		return fmt.Errorf("skill '%s' not found in registry", skillName)
	}

	// Fetch Manifest
	resp, err := http.Get(target.ManifestURL)
	if err != nil {
		return fmt.Errorf("failed to fetch manifest: %w", err)
	}
	defer resp.Body.Close()

	var m Manifest
	if err := yaml.NewDecoder(resp.Body).Decode(&m); err != nil {
		return fmt.Errorf("failed to parse manifest from registry: %w", err)
	}

	// Verify Signature
	valid, err := m.VerifySignature(trustKeys)
	if err != nil {
		return fmt.Errorf("signature verification error: %w", err)
	}
	if !valid {
		return fmt.Errorf("SECURITY ALERT: Skill signature verification failed! Possible tampering detected")
	}

	// Create directory and save
	skillPath := filepath.Join(destDir, skillName)
	if err := os.MkdirAll(skillPath, 0700); err != nil {
		return fmt.Errorf("failed to create skill directory: %w", err)
	}

	manifestPath := filepath.Join(skillPath, "skill.yaml")
	data, _ := yaml.Marshal(m)
	if err := os.WriteFile(manifestPath, data, 0600); err != nil {
		return fmt.Errorf("failed to save skill manifest: %w", err)
	}

	fmt.Printf("✅ Successfully installed skill: %s v%s\n", m.Name, m.Version)
	return nil
}
