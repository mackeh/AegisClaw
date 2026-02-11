package secrets

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// VaultStore implements Store using HashiCorp Vault's KV v2 API.
type VaultStore struct {
	address string
	token   string
	mount   string
	path    string
	client  *http.Client
}

// VaultConfig holds configuration for connecting to Vault.
type VaultConfig struct {
	Address  string `yaml:"address"`   // e.g. "https://vault.example.com"
	TokenEnv string `yaml:"token_env"` // env var name holding the token (e.g. "VAULT_TOKEN")
	Mount    string `yaml:"mount"`     // KV mount path (e.g. "secret")
	Path     string `yaml:"path"`      // base path within the mount (e.g. "aegisclaw")
}

// NewVaultStore creates a Vault-backed secret store.
func NewVaultStore(cfg VaultConfig) (*VaultStore, error) {
	token := os.Getenv(cfg.TokenEnv)
	if token == "" {
		return nil, fmt.Errorf("vault token not found in environment variable %s", cfg.TokenEnv)
	}

	address := strings.TrimRight(cfg.Address, "/")
	mount := cfg.Mount
	if mount == "" {
		mount = "secret"
	}
	path := cfg.Path
	if path == "" {
		path = "aegisclaw"
	}

	return &VaultStore{
		address: address,
		token:   token,
		mount:   mount,
		path:    path,
		client:  &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (v *VaultStore) Get(key string) (string, error) {
	url := fmt.Sprintf("%s/v1/%s/data/%s/%s", v.address, v.mount, v.path, key)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Vault-Token", v.token)

	resp, err := v.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("vault request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("secret '%s' not found", key)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("vault returned status %d", resp.StatusCode)
	}

	var result struct {
		Data struct {
			Data map[string]interface{} `json:"data"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode vault response: %w", err)
	}

	val, ok := result.Data.Data["value"]
	if !ok {
		return "", fmt.Errorf("secret '%s' has no 'value' field", key)
	}

	return fmt.Sprintf("%v", val), nil
}

func (v *VaultStore) Set(key, value string) error {
	url := fmt.Sprintf("%s/v1/%s/data/%s/%s", v.address, v.mount, v.path, key)

	payload := map[string]interface{}{
		"data": map[string]string{
			"value": value,
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", v.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("vault request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("vault returned status %d", resp.StatusCode)
	}

	return nil
}

func (v *VaultStore) Delete(key string) error {
	url := fmt.Sprintf("%s/v1/%s/metadata/%s/%s", v.address, v.mount, v.path, key)

	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", v.token)

	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("vault request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("vault returned status %d", resp.StatusCode)
	}
	return nil
}

func (v *VaultStore) List() ([]string, error) {
	url := fmt.Sprintf("%s/v1/%s/metadata/%s?list=true", v.address, v.mount, v.path)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", v.token)

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return []string{}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vault returned status %d", resp.StatusCode)
	}

	var result struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode vault response: %w", err)
	}

	return result.Data.Keys, nil
}
