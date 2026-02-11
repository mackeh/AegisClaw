package secrets

import (
	"os"
	"path/filepath"
	"testing"
)

func TestManager_Init(t *testing.T) {
	tmp := t.TempDir()
	mgr := NewManager(tmp)

	pubKey, err := mgr.Init()
	if err != nil {
		t.Fatalf("init error: %v", err)
	}
	if pubKey == "" {
		t.Fatal("expected non-empty public key")
	}

	// Keys file should exist
	if _, err := os.Stat(filepath.Join(tmp, "keys.txt")); err != nil {
		t.Fatalf("expected keys.txt to exist: %v", err)
	}

	// Second init should fail
	_, err = mgr.Init()
	if err == nil {
		t.Fatal("expected error on second init")
	}
}

func TestManager_SetGetList(t *testing.T) {
	tmp := t.TempDir()
	mgr := NewManager(tmp)

	_, err := mgr.Init()
	if err != nil {
		t.Fatalf("init error: %v", err)
	}

	// Set a secret
	if err := mgr.Set("API_KEY", "sk-test-12345"); err != nil {
		t.Fatalf("set error: %v", err)
	}

	// Get it back
	val, err := mgr.Get("API_KEY")
	if err != nil {
		t.Fatalf("get error: %v", err)
	}
	if val != "sk-test-12345" {
		t.Errorf("expected 'sk-test-12345', got '%s'", val)
	}

	// List secrets
	keys, err := mgr.List()
	if err != nil {
		t.Fatalf("list error: %v", err)
	}
	if len(keys) != 1 || keys[0] != "API_KEY" {
		t.Errorf("expected [API_KEY], got %v", keys)
	}
}

func TestManager_GetNotFound(t *testing.T) {
	tmp := t.TempDir()
	mgr := NewManager(tmp)

	_, err := mgr.Init()
	if err != nil {
		t.Fatalf("init error: %v", err)
	}

	// Set a value first to create the secrets file
	mgr.Set("DUMMY", "val")

	_, err = mgr.Get("NONEXISTENT")
	if err == nil {
		t.Fatal("expected error for nonexistent key")
	}
}

func TestManager_SetMultiple(t *testing.T) {
	tmp := t.TempDir()
	mgr := NewManager(tmp)

	_, err := mgr.Init()
	if err != nil {
		t.Fatalf("init error: %v", err)
	}

	mgr.Set("KEY1", "val1")
	mgr.Set("KEY2", "val2")
	mgr.Set("KEY3", "val3")

	keys, err := mgr.List()
	if err != nil {
		t.Fatalf("list error: %v", err)
	}
	if len(keys) != 3 {
		t.Errorf("expected 3 keys, got %d", len(keys))
	}
}

func TestManager_Overwrite(t *testing.T) {
	tmp := t.TempDir()
	mgr := NewManager(tmp)

	_, err := mgr.Init()
	if err != nil {
		t.Fatalf("init error: %v", err)
	}

	mgr.Set("KEY", "original")
	mgr.Set("KEY", "updated")

	val, err := mgr.Get("KEY")
	if err != nil {
		t.Fatalf("get error: %v", err)
	}
	if val != "updated" {
		t.Errorf("expected 'updated', got '%s'", val)
	}
}

func TestManager_ListEmpty(t *testing.T) {
	tmp := t.TempDir()
	mgr := NewManager(tmp)

	// No init, no secrets file - should return empty list
	keys, err := mgr.List()
	if err != nil {
		t.Fatalf("list error: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("expected 0 keys, got %d", len(keys))
	}
}

func TestAgeStore(t *testing.T) {
	tmp := t.TempDir()
	store := NewAgeStore(tmp)

	// Init the underlying manager
	mgr := NewManager(tmp)
	if _, err := mgr.Init(); err != nil {
		t.Fatalf("init error: %v", err)
	}

	// Set via store
	if err := store.Set("TEST_KEY", "test_value"); err != nil {
		t.Fatalf("set error: %v", err)
	}

	// Get via store
	val, err := store.Get("TEST_KEY")
	if err != nil {
		t.Fatalf("get error: %v", err)
	}
	if val != "test_value" {
		t.Errorf("expected 'test_value', got '%s'", val)
	}

	// List via store
	keys, err := store.List()
	if err != nil {
		t.Fatalf("list error: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("expected 1 key, got %d", len(keys))
	}

	// Delete via store
	if err := store.Delete("TEST_KEY"); err != nil {
		t.Fatalf("delete error: %v", err)
	}

	keys, err = store.List()
	if err != nil {
		t.Fatalf("list error: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("expected 0 keys after delete, got %d", len(keys))
	}
}

func TestVaultStore_MissingToken(t *testing.T) {
	os.Unsetenv("VAULT_TOKEN_TEST_MISSING")
	_, err := NewVaultStore(VaultConfig{
		Address:  "https://vault.example.com",
		TokenEnv: "VAULT_TOKEN_TEST_MISSING",
	})
	if err == nil {
		t.Fatal("expected error for missing vault token")
	}
}

func TestVaultStore_NewWithDefaults(t *testing.T) {
	t.Setenv("VAULT_TOKEN_TEST", "test-token")
	store, err := NewVaultStore(VaultConfig{
		Address:  "https://vault.example.com",
		TokenEnv: "VAULT_TOKEN_TEST",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if store.mount != "secret" {
		t.Errorf("expected default mount 'secret', got '%s'", store.mount)
	}
	if store.path != "aegisclaw" {
		t.Errorf("expected default path 'aegisclaw', got '%s'", store.path)
	}
}
