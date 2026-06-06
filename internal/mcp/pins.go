package mcp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// toolHash fingerprints a tool's name, description, and input schema. A change
// in any of these between runs is the signature of a tool-poisoning / rug-pull
// attack — a server silently altering what a tool does after first approval.
func toolHash(t Tool) string {
	schema, _ := json.Marshal(t.InputSchema)
	h := sha256.New()
	h.Write([]byte(t.Name))
	h.Write([]byte{0})
	h.Write([]byte(t.Description))
	h.Write([]byte{0})
	h.Write(schema)
	return hex.EncodeToString(h.Sum(nil))
}

// PinStore records the trusted hash of each tool's description/schema. New tools
// are pinned on first sight (trust-on-first-use); a later mismatch quarantines
// the tool until an operator re-approves it.
type PinStore struct {
	path string
	mu   sync.Mutex
	pins map[string]string // tool name -> trusted hash
}

// NewPinStore loads (or creates) a pin store backed by path.
func NewPinStore(path string) (*PinStore, error) {
	ps := &PinStore{path: path, pins: make(map[string]string)}
	if err := ps.load(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return ps, nil
}

// NewMemoryPinStore returns an in-memory pin store (no persistence).
func NewMemoryPinStore() *PinStore {
	return &PinStore{pins: make(map[string]string)}
}

// Get returns the trusted hash for a tool and whether one is recorded.
func (p *PinStore) Get(name string) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	h, ok := p.pins[name]
	return h, ok
}

// Set records (or updates) the trusted hash for a tool.
func (p *PinStore) Set(name, hash string) {
	p.mu.Lock()
	p.pins[name] = hash
	p.mu.Unlock()
}

// Names returns the pinned tool names, unsorted.
func (p *PinStore) Names() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	names := make([]string, 0, len(p.pins))
	for n := range p.pins {
		names = append(names, n)
	}
	return names
}

// Remove deletes a tool's pin so it is re-pinned (trust-on-first-use) the next
// time it is seen — the operator action that re-approves a changed tool.
func (p *PinStore) Remove(name string) {
	p.mu.Lock()
	delete(p.pins, name)
	p.mu.Unlock()
}

func (p *PinStore) load() error {
	if p.path == "" {
		return nil
	}
	data, err := os.ReadFile(p.path)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return json.Unmarshal(data, &p.pins)
}

// Save persists the pins to disk (no-op for an in-memory store).
func (p *PinStore) Save() error {
	if p.path == "" {
		return nil
	}
	p.mu.Lock()
	data, err := json.MarshalIndent(p.pins, "", "  ")
	p.mu.Unlock()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p.path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(p.path, data, 0o600)
}
