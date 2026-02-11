// Package notifications provides event alerting for AegisClaw.
// It supports webhook and Slack transports, dispatching events like
// pending approvals, denied actions, and emergency lockdowns.
package notifications

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Event represents a notification event type.
type Event string

const (
	EventApprovalPending   Event = "approval_pending"
	EventActionDenied      Event = "action_denied"
	EventEmergencyLockdown Event = "emergency_lockdown"
	EventSkillCompleted    Event = "skill_completed"
	EventSecretLeakDetected Event = "secret_leak"
)

// Payload carries the notification data.
type Payload struct {
	Event     Event          `json:"event"`
	Timestamp time.Time      `json:"timestamp"`
	Skill     string         `json:"skill,omitempty"`
	Command   string         `json:"command,omitempty"`
	Decision  string         `json:"decision,omitempty"`
	Scopes    []string       `json:"scopes,omitempty"`
	Details   map[string]any `json:"details,omitempty"`
}

// Notifier is the interface for sending notifications.
type Notifier interface {
	Send(ctx context.Context, payload Payload) error
	Handles(event Event) bool
}

// Dispatcher fans out notifications to all registered notifiers.
type Dispatcher struct {
	notifiers []Notifier
}

// NewDispatcher creates a dispatcher from configuration.
func NewDispatcher(configs []NotifierConfig) *Dispatcher {
	d := &Dispatcher{}
	for _, cfg := range configs {
		switch cfg.Type {
		case "webhook":
			d.notifiers = append(d.notifiers, NewWebhookNotifier(cfg.URL, cfg.Secret, cfg.Events))
		case "slack":
			d.notifiers = append(d.notifiers, NewSlackNotifier(cfg.WebhookURL, cfg.Events))
		}
	}
	return d
}

// Notify sends a payload to all notifiers that handle this event type.
func (d *Dispatcher) Notify(ctx context.Context, payload Payload) {
	for _, n := range d.notifiers {
		if n.Handles(payload.Event) {
			// Fire and forget — don't block the caller.
			go n.Send(ctx, payload)
		}
	}
}

// NotifierConfig represents a notification channel from config.yaml.
type NotifierConfig struct {
	Type       string  `yaml:"type"`
	URL        string  `yaml:"url,omitempty"`
	Secret     string  `yaml:"secret,omitempty"`
	WebhookURL string  `yaml:"webhook_url,omitempty"`
	Events     []Event `yaml:"events"`
}

// --- Webhook Notifier ---

// WebhookNotifier sends HMAC-signed HTTP POST payloads.
type WebhookNotifier struct {
	url    string
	secret string
	events map[Event]bool
	client *http.Client
}

// NewWebhookNotifier creates a new WebhookNotifier.
func NewWebhookNotifier(url, secret string, events []Event) *WebhookNotifier {
	m := make(map[Event]bool)
	for _, e := range events {
		m[e] = true
	}
	return &WebhookNotifier{
		url:    url,
		secret: secret,
		events: m,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Handles returns true if this notifier is subscribed to the event.
func (w *WebhookNotifier) Handles(event Event) bool {
	return len(w.events) == 0 || w.events[event]
}

// Send dispatches the payload via HTTP POST with HMAC signature.
func (w *WebhookNotifier) Send(ctx context.Context, payload Payload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("webhook: marshal failed: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook: request creation failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "AegisClaw-Notification/1.0")

	if w.secret != "" {
		mac := hmac.New(sha256.New, []byte(w.secret))
		mac.Write(body)
		sig := hex.EncodeToString(mac.Sum(nil))
		req.Header.Set("X-AegisClaw-Signature", sig)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: send failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook: server returned %d", resp.StatusCode)
	}
	return nil
}

// --- Slack Notifier ---

// SlackNotifier sends messages to a Slack incoming webhook.
type SlackNotifier struct {
	webhookURL string
	events     map[Event]bool
	client     *http.Client
}

// NewSlackNotifier creates a new SlackNotifier.
func NewSlackNotifier(webhookURL string, events []Event) *SlackNotifier {
	m := make(map[Event]bool)
	for _, e := range events {
		m[e] = true
	}
	return &SlackNotifier{
		webhookURL: webhookURL,
		events:     m,
		client:     &http.Client{Timeout: 10 * time.Second},
	}
}

// Handles returns true if this notifier is subscribed to the event.
func (s *SlackNotifier) Handles(event Event) bool {
	return len(s.events) == 0 || s.events[event]
}

// Send dispatches the notification as a Slack message.
func (s *SlackNotifier) Send(ctx context.Context, payload Payload) error {
	msg := formatSlackMessage(payload)

	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("slack: marshal failed: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("slack: request creation failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("slack: send failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("slack: server returned %d", resp.StatusCode)
	}
	return nil
}

type slackMessage struct {
	Text   string          `json:"text"`
	Blocks json.RawMessage `json:"blocks,omitempty"`
}

func formatSlackMessage(p Payload) slackMessage {
	var icon, title string
	switch p.Event {
	case EventApprovalPending:
		icon = ":warning:"
		title = "Approval Pending"
	case EventActionDenied:
		icon = ":no_entry:"
		title = "Action Denied"
	case EventEmergencyLockdown:
		icon = ":rotating_light:"
		title = "EMERGENCY LOCKDOWN"
	case EventSkillCompleted:
		icon = ":white_check_mark:"
		title = "Skill Completed"
	case EventSecretLeakDetected:
		icon = ":lock:"
		title = "Secret Leak Detected"
	default:
		icon = ":bell:"
		title = string(p.Event)
	}

	text := fmt.Sprintf("%s *AegisClaw — %s*", icon, title)
	if p.Skill != "" {
		text += fmt.Sprintf("\nSkill: `%s`", p.Skill)
	}
	if p.Command != "" {
		text += fmt.Sprintf(" | Command: `%s`", p.Command)
	}
	if p.Decision != "" {
		text += fmt.Sprintf("\nDecision: `%s`", p.Decision)
	}

	return slackMessage{Text: text}
}
