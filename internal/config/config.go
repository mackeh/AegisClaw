// Package config provides configuration loading and management for AegisClaw.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config represents the main AegisClaw configuration
type Config struct {
	Version  string         `yaml:"version"`
	Agent    AgentConfig    `yaml:"agent"`
	Security SecurityConfig `yaml:"security"`
	Network  NetworkConfig  `yaml:"network"`
	Registry RegistryConfig `yaml:"registry"`
	Telemetry TelemetryConfig `yaml:"telemetry"`
}

// TelemetryConfig contains observability settings
type TelemetryConfig struct {
	Enabled bool   `yaml:"enabled"`
	Exporter string `yaml:"exporter"` // e.g., "stdout", "otlp", "none"
}

// RegistryConfig contains skill registry settings
type RegistryConfig struct {
	URL       string   `yaml:"url"`
	TrustKeys []string `yaml:"trust_keys"` // Public keys of trusted signers
}

// AgentConfig contains agent-specific settings
type AgentConfig struct {
	Name    string `yaml:"name"`
	Enabled bool   `yaml:"enabled"`
}

// SecurityConfig contains security-related settings
type SecurityConfig struct {
	SandboxBackend  string `yaml:"sandbox_backend"`
	SandboxRuntime  string `yaml:"sandbox_runtime"` // e.g. "runsc"
	RequireApproval bool   `yaml:"require_approval"`
	AuditEnabled    bool   `yaml:"audit_enabled"`
}

// NetworkConfig contains network isolation settings
type NetworkConfig struct {
	DefaultDeny bool     `yaml:"default_deny"`
	Allowlist   []string `yaml:"allowlist"`
}

// DefaultConfigDir returns the default configuration directory path
func DefaultConfigDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}
	return filepath.Join(home, ".aegisclaw"), nil
}

// Load reads the configuration from the specified path
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return &cfg, nil
}

// LoadDefault loads configuration from the default path
func LoadDefault() (*Config, error) {
	dir, err := DefaultConfigDir()
	if err != nil {
		return nil, err
	}
	return Load(filepath.Join(dir, "config.yaml"))
}

// Save writes the configuration to the specified path
func (c *Config) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}
