package doctor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckConfigDir_Missing(t *testing.T) {
	result := checkConfigDir("/nonexistent/path")
	if result.Status != StatusFail {
		t.Errorf("expected StatusFail for missing dir, got %d", result.Status)
	}
}

func TestCheckConfigDir_Exists(t *testing.T) {
	dir := t.TempDir()
	result := checkConfigDir(dir)
	if result.Status != StatusPass {
		t.Errorf("expected StatusPass for existing dir, got %d", result.Status)
	}
}

func TestCheckPolicy_Missing(t *testing.T) {
	dir := t.TempDir()
	result := checkPolicy(dir)
	if result.Status != StatusFail {
		t.Errorf("expected StatusFail for missing policy, got %d", result.Status)
	}
}

func TestCheckPolicy_Exists(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.rego")
	os.WriteFile(policyPath, []byte("package aegisclaw.policy"), 0600)

	result := checkPolicy(dir)
	if result.Status != StatusPass {
		t.Errorf("expected StatusPass for existing policy, got %d", result.Status)
	}
}

func TestCheckSecrets_NoDir(t *testing.T) {
	dir := t.TempDir()
	result := checkSecrets(dir)
	if result.Status != StatusWarn {
		t.Errorf("expected StatusWarn for missing secrets dir, got %d", result.Status)
	}
}

func TestCheckSecrets_NoKeys(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "secrets"), 0700)

	result := checkSecrets(dir)
	if result.Status != StatusWarn {
		t.Errorf("expected StatusWarn for uninitialized secrets, got %d", result.Status)
	}
}

func TestCheckAuditLog_Empty(t *testing.T) {
	dir := t.TempDir()
	result := checkAuditLog(dir)
	if result.Status != StatusPass {
		t.Errorf("expected StatusPass for empty audit log, got %d", result.Status)
	}
}

func TestCheckDiskSpace(t *testing.T) {
	dir := t.TempDir()
	result := checkDiskSpace(dir)
	// Should pass or warn on any real filesystem
	if result.Status == StatusFail {
		t.Logf("disk space check failed (may be expected in constrained env): %s", result.Detail)
	}
}
