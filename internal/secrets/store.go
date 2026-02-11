package secrets

// Store defines the interface for pluggable secret backends.
// Implementations: AgeStore (default), VaultStore, etc.
type Store interface {
	// Get retrieves a secret by key.
	Get(key string) (string, error)

	// Set stores a secret.
	Set(key string, value string) error

	// Delete removes a secret.
	Delete(key string) error

	// List returns all secret key names (not values).
	List() ([]string, error)
}

// AgeStore wraps the existing Manager as a Store implementation.
type AgeStore struct {
	mgr *Manager
}

// NewAgeStore creates a Store backed by age encryption.
func NewAgeStore(configDir string) *AgeStore {
	return &AgeStore{mgr: NewManager(configDir)}
}

func (s *AgeStore) Get(key string) (string, error) {
	return s.mgr.Get(key)
}

func (s *AgeStore) Set(key, value string) error {
	return s.mgr.Set(key, value)
}

func (s *AgeStore) Delete(key string) error {
	secrets, err := s.mgr.loadAll()
	if err != nil {
		return err
	}
	delete(secrets, key)
	return s.mgr.saveAll(secrets)
}

func (s *AgeStore) List() ([]string, error) {
	return s.mgr.List()
}
