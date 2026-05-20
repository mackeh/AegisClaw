package server

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mackeh/AegisClaw/internal/config"
	"gopkg.in/yaml.v3"
)

// configured reports whether the auth config can actually gate access — it is
// enabled and has at least one API key. A config that is enabled but keyless
// would lock everyone out, so it does not count as configured.
func (c AuthConfig) configured() bool {
	return c.Enabled && len(c.Keys) > 0
}

// LoadAuthConfig reads API authentication settings from
// ~/.aegisclaw/auth.yaml. A missing file is not an error: it yields a
// disabled (pass-through) config. The file is kept separate from the main
// config.yaml because it holds secret tokens.
func LoadAuthConfig() (AuthConfig, error) {
	dir, err := config.DefaultConfigDir()
	if err != nil {
		return AuthConfig{}, err
	}
	return loadAuthConfig(filepath.Join(dir, "auth.yaml"))
}

func loadAuthConfig(path string) (AuthConfig, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return AuthConfig{}, nil
	}
	if err != nil {
		return AuthConfig{}, fmt.Errorf("failed to read auth config: %w", err)
	}

	var cfg AuthConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return AuthConfig{}, fmt.Errorf("failed to parse auth config: %w", err)
	}
	return cfg, nil
}
