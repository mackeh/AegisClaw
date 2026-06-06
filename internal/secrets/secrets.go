package secrets

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"filippo.io/age"
	"gopkg.in/yaml.v3"
)

// Manager handles secret encryption and storage
type Manager struct {
	configDir string
	keyFile   string
}

// NewManager creates a new secrets manager
func NewManager(configDir string) *Manager {
	return &Manager{
		configDir: configDir,
		keyFile:   filepath.Join(configDir, "keys.txt"),
	}
}

// Init generates a new age Identity (keypair) if one doesn't exist
func (m *Manager) Init() (string, error) {
	if _, err := os.Stat(m.keyFile); err == nil {
		return "", fmt.Errorf("keys already exist at %s", m.keyFile)
	}

	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return "", fmt.Errorf("failed to generate identity: %w", err)
	}

	// Save private key
	f, err := os.OpenFile(m.keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return "", fmt.Errorf("failed to create key file: %w", err)
	}
	defer f.Close()

	if _, err := fmt.Fprintf(f, "%s\n", identity.String()); err != nil {
		return "", err
	}

	if _, err := fmt.Fprintf(f, "# Public key: %s\n", identity.Recipient().String()); err != nil {
		return "", err
	}

	return identity.Recipient().String(), nil
}

// Set encrypts and stores a secret value
func (m *Manager) Set(key, value string) error {
	secrets, err := m.loadAll()
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if secrets == nil {
		secrets = make(map[string]string)
	}

	secrets[key] = value
	return m.saveAll(secrets)
}

// Get retrieves and decrypts a specific secret
func (m *Manager) Get(key string) (string, error) {
	secrets, err := m.loadAll()
	if err != nil {
		return "", err
	}
	val, ok := secrets[key]
	if !ok {
		return "", fmt.Errorf("secret '%s' not found", key)
	}
	return val, nil
}

// List returns the names of all stored secrets
func (m *Manager) List() ([]string, error) {
	secrets, err := m.loadAll()
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}

	keys := make([]string, 0, len(secrets))
	for k := range secrets {
		keys = append(keys, k)
	}
	return keys, nil
}

func (m *Manager) loadAll() (map[string]string, error) {
	secretsPath := filepath.Join(m.configDir, "secrets.enc")
	if _, err := os.Stat(secretsPath); os.IsNotExist(err) {
		return nil, err
	}

	// 1. Load identity
	identity, err := m.getIdentity()
	if err != nil {
		return nil, err
	}

	// 2. Read encrypted file
	f, err := os.Open(secretsPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// 3. Decrypt
	r, err := age.Decrypt(f, identity)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt secrets: %w", err)
	}

	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	// 4. Parse YAML
	var secrets map[string]string
	if err := yaml.Unmarshal(data, &secrets); err != nil {
		return nil, err
	}

	return secrets, nil
}

func (m *Manager) saveAll(secrets map[string]string) error {
	secretsPath := filepath.Join(m.configDir, "secrets.enc")

	// 1. Get recipient
	identity, err := m.getIdentity()
	if err != nil {
		return err
	}
	recipient := identity.Recipient()

	// 2. Marshal secrets
	data, err := yaml.Marshal(secrets)
	if err != nil {
		return err
	}

	// 3. Encrypt
	buf := &bytes.Buffer{}
	w, err := age.Encrypt(buf, recipient)
	if err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}

	// 4. Write to disk
	return os.WriteFile(secretsPath, buf.Bytes(), 0600)
}

func (m *Manager) getIdentity() (*age.X25519Identity, error) {
	data, err := os.ReadFile(m.keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file (run 'secrets init'): %w", err)
	}

	// Parse first non-comment line
	lines := bytes.Split(data, []byte("\n"))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		return age.ParseX25519Identity(string(line))
	}

	return nil, fmt.Errorf("no identity found in key file")
}