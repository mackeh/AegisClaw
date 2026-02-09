package skill

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
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
