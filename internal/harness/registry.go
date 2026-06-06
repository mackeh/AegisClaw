package harness

import (
	"fmt"
	"sort"
	"sync"
)

// Registry maps adapter names to implementations. It is safe for concurrent
// use. Adapters are registered explicitly by the caller (the CLI) rather than
// via package init so the dependency direction stays one-way (adapter packages
// import harness, never the reverse) and tests can build isolated registries.
type Registry struct {
	mu       sync.RWMutex
	adapters map[string]AgentAdapter
}

// NewRegistry creates an empty adapter registry.
func NewRegistry() *Registry {
	return &Registry{adapters: make(map[string]AgentAdapter)}
}

// Register adds an adapter, keyed by its Name(). A later registration with the
// same name replaces the earlier one.
func (r *Registry) Register(a AgentAdapter) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.adapters[a.Name()] = a
}

// Get returns the adapter registered under name.
func (r *Registry) Get(name string) (AgentAdapter, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.adapters[name]
	if !ok {
		return nil, fmt.Errorf("unknown agent adapter %q (available: %v)", name, r.namesLocked())
	}
	return a, nil
}

// Names returns the registered adapter names, sorted.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.namesLocked()
}

func (r *Registry) namesLocked() []string {
	names := make([]string, 0, len(r.adapters))
	for n := range r.adapters {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
