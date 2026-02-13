package skill

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSignatureVerification(t *testing.T) {
	// 1. Generate keys
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pubHex := hex.EncodeToString(pub)

	// 2. Create manifest
	m := Manifest{
		Name:        "test-skill",
		Version:     "1.0.0",
		Description: "A test skill",
		Image:       "alpine:latest",
		Commands:    map[string]Command{"hello": {Args: []string{"echo", "hi"}}},
	}

	// 3. Sign manifest
	data, _ := json.Marshal(m)
	sig := ed25519.Sign(priv, data)
	m.Signature = hex.EncodeToString(sig)

	// 4. Verify (Success)
	valid, err := m.VerifySignature([]string{pubHex})
	if err != nil {
		t.Errorf("VerifySignature returned error: %v", err)
	}
	if !valid {
		t.Error("VerifySignature failed for valid signature")
	}

	// 5. Verify (Failure - Wrong Key)
	_, priv2, _ := ed25519.GenerateKey(nil)
	sig2 := ed25519.Sign(priv2, data)
	m.Signature = hex.EncodeToString(sig2)

	valid, _ = m.VerifySignature([]string{pubHex})
	if valid {
		t.Error("VerifySignature succeeded for wrong public key")
	}

	// 6. Verify (Failure - Tampered Content)
	m.Signature = hex.EncodeToString(sig) // back to valid signature
	m.Description = "Tampered description"

	valid, _ = m.VerifySignature([]string{pubHex})
	if valid {
		t.Error("VerifySignature succeeded for tampered content")
	}
}

func TestLoadManifest_PathValidation(t *testing.T) {
	tmp := t.TempDir()
	manifestDir := filepath.Join(tmp, "safe")
	if err := os.MkdirAll(manifestDir, 0700); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(manifestDir, "skill.yaml")
	content := "name: test\nversion: \"1.0.0\"\nimage: alpine:latest\ncommands:\n  run:\n    args: [\"echo\", \"ok\"]\nscopes: []\n"
	if err := os.WriteFile(manifestPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadManifest(manifestPath); err != nil {
		t.Fatalf("expected valid manifest path, got error: %v", err)
	}

	if _, err := LoadManifest(filepath.Join(tmp, "safe", "not-skill.yaml")); err == nil {
		t.Fatal("expected error for non-skill.yaml path")
	}
}

func TestValidateSkillName(t *testing.T) {
	valid := []string{"hello-world", "skill_1", "a.b"}
	for _, name := range valid {
		if err := validateSkillName(name); err != nil {
			t.Fatalf("expected valid name %q, got error %v", name, err)
		}
	}

	invalid := []string{"", ".", "..", "../x", "a/b", `a\b`}
	for _, name := range invalid {
		if err := validateSkillName(name); err == nil {
			t.Fatalf("expected invalid name %q to fail", name)
		}
	}
}
