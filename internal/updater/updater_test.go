package updater

import (
	"testing"
)

func TestCheck(t *testing.T) {
	// This test might fail in CI if GitHub API rate limits it,
	// but it's good for local verification.
	tag, err := Check("0.0.1")
	if err != nil {
		t.Skip("Skipping Check test: ", err)
	}

	if tag == "" {
		t.Log("No update found (this is possible if current matches latest)")
	} else {
		t.Logf("Found latest tag: %s", tag)
	}
}
