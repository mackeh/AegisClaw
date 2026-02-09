package approval

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Decision represents a persistent approval
type Decision struct {
	Hash        string    `json:"hash"` // Hash of scope+constraints
	Decision    string    `json:"decision"` // "always"
	Scope       string    `json:"scope"`
	GrantedAt   time.Time `json:"granted_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type Store struct {
	path      string
	decisions map[string]Decision
	mu        sync.RWMutex
}

func NewStore() (*Store, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	
	path := filepath.Join(home, ".aegisclaw", "approvals.json")
	store := &Store{
		path:      path,
		decisions: make(map[string]Decision),
	}
	
	if err := store.load(); err != nil {
		// Verify if file exists, if not it's fine
		if !os.IsNotExist(err) {
			return nil, err
		}
	}
	
	return store, nil
}

func (s *Store) Check(scopeStr string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	hash := hashScope(scopeStr)
	if d, ok := s.decisions[hash]; ok {
		if d.ExpiresAt.IsZero() || d.ExpiresAt.After(time.Now()) {
			return d.Decision
		}
	}
	return ""
}

func (s *Store) Grant(scopeStr string, decisionStr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	hash := hashScope(scopeStr)
	
	d := Decision{
		Hash:      hash,
		Decision:  decisionStr,
		Scope:     scopeStr,
		GrantedAt: time.Now(),
	}
	
	// "Always" grants expire in 30 days by default
	if decisionStr == "always" {
		d.ExpiresAt = time.Now().Add(30 * 24 * time.Hour)
	}

	s.decisions[hash] = d
	return s.save()
}

func (s *Store) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &s.decisions)
}

func (s *Store) save() error {
	data, err := json.MarshalIndent(s.decisions, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0600)
}

func hashScope(s string) string {
	h := sha256.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}
