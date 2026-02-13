package openclaw

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mackeh/AegisClaw/internal/secrets"
	"gopkg.in/yaml.v3"
)

// AdapterConfig represents ~/.aegisclaw/adapters/openclaw.yaml.
type AdapterConfig struct {
	Enabled      bool   `yaml:"enabled"`
	Endpoint     string `yaml:"endpoint"`
	APIKeySecret string `yaml:"api_key_secret"`
	TimeoutMS    int    `yaml:"timeout_ms"`
}

// Status values returned by CheckHealth.
const (
	StatusConnected     = "connected"
	StatusDegraded      = "degraded"
	StatusUnreachable   = "unreachable"
	StatusDisabled      = "disabled"
	StatusNotConfigured = "not_configured"
	StatusInvalidConfig = "invalid_config"
	StatusInvalidEP     = "invalid_endpoint"
	StatusConfigError   = "config_error"
)

// Health is the normalized OpenClaw adapter health response.
type Health struct {
	Status           string `json:"status"`
	Configured       bool   `json:"configured"`
	Enabled          bool   `json:"enabled"`
	Connected        bool   `json:"connected"`
	Ready            bool   `json:"ready"`
	Endpoint         string `json:"endpoint,omitempty"`
	LatencyMS        int64  `json:"latency_ms,omitempty"`
	HTTPStatus       int    `json:"http_status,omitempty"`
	SecretConfigured bool   `json:"secret_configured"`
	SecretPresent    bool   `json:"secret_present"`
	Message          string `json:"message"`
}

// CheckHealth validates adapter config, endpoint reachability, and secret wiring.
func CheckHealth(cfgDir string) Health {
	adapterPath := filepath.Join(cfgDir, "adapters", "openclaw.yaml")
	data, err := os.ReadFile(adapterPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Health{
				Status:     StatusNotConfigured,
				Configured: false,
				Message:    "openclaw adapter config not found",
			}
		}
		return Health{
			Status:     StatusConfigError,
			Configured: false,
			Message:    fmt.Sprintf("failed to read adapter config: %v", err),
		}
	}

	var cfg AdapterConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Health{
			Status:     StatusInvalidConfig,
			Configured: true,
			Message:    fmt.Sprintf("invalid adapter config: %v", err),
		}
	}

	h := Health{
		Configured:       true,
		Enabled:          cfg.Enabled,
		Endpoint:         strings.TrimSpace(cfg.Endpoint),
		SecretConfigured: strings.TrimSpace(cfg.APIKeySecret) != "",
	}

	if !cfg.Enabled {
		h.Status = StatusDisabled
		h.Message = "adapter is configured but disabled"
		return h
	}

	if h.Endpoint == "" {
		h.Status = StatusInvalidEP
		h.Message = "adapter endpoint is empty"
		return h
	}

	u, err := url.Parse(h.Endpoint)
	if err != nil || u.Scheme == "" || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		h.Status = StatusInvalidEP
		h.Message = fmt.Sprintf("invalid endpoint URL: %q", h.Endpoint)
		return h
	}

	timeout := 3 * time.Second
	if cfg.TimeoutMS > 0 {
		timeout = time.Duration(cfg.TimeoutMS) * time.Millisecond
	}
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest(http.MethodGet, h.Endpoint, nil)
	if err != nil {
		h.Status = StatusInvalidEP
		h.Message = fmt.Sprintf("invalid endpoint request: %v", err)
		return h
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		h.Status = StatusUnreachable
		h.Message = fmt.Sprintf("endpoint unreachable: %v", err)
		return h
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	h.Connected = true
	h.LatencyMS = time.Since(start).Milliseconds()
	h.HTTPStatus = resp.StatusCode

	if h.SecretConfigured {
		secretName := strings.TrimSpace(cfg.APIKeySecret)
		secretMgr := secrets.NewManager(filepath.Join(cfgDir, "secrets"))
		if _, err := secretMgr.Get(secretName); err == nil {
			h.SecretPresent = true
		}
	}

	if resp.StatusCode >= 500 || !h.SecretConfigured || !h.SecretPresent {
		h.Status = StatusDegraded
		h.Ready = false
		switch {
		case resp.StatusCode >= 500:
			h.Message = fmt.Sprintf("endpoint returned server error (%d)", resp.StatusCode)
		case !h.SecretConfigured:
			h.Message = "endpoint reachable but api_key_secret is not configured"
		default:
			h.Message = "endpoint reachable but configured api_key_secret is missing"
		}
		return h
	}

	h.Status = StatusConnected
	h.Ready = true
	h.Message = "adapter reachable and ready"
	return h
}
