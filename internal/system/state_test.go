package system

import "testing"

func TestLockdownCycle(t *testing.T) {
	// Ensure clean state
	Unlock()

	if IsLockedDown() {
		t.Error("expected not locked down initially")
	}

	Lockdown()
	if !IsLockedDown() {
		t.Error("expected locked down after Lockdown()")
	}

	Unlock()
	if IsLockedDown() {
		t.Error("expected not locked down after Unlock()")
	}
}

func TestDoubleLockdown(t *testing.T) {
	Unlock()

	Lockdown()
	Lockdown() // should not panic
	if !IsLockedDown() {
		t.Error("expected still locked down")
	}

	Unlock()
}

func TestDoubleUnlock(t *testing.T) {
	Unlock()
	Unlock() // should not panic
	if IsLockedDown() {
		t.Error("expected not locked down")
	}
}
