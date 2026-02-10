package system

import "sync"

var (
	lockdownMode bool
	mu           sync.RWMutex
)

// IsLockedDown returns true if the system is in emergency lockdown
func IsLockedDown() bool {
	mu.RLock()
	defer mu.RUnlock()
	return lockdownMode
}

// Lockdown enables emergency lockdown mode
func Lockdown() {
	mu.Lock()
	defer mu.Unlock()
	lockdownMode = true
}

// Unlock disables emergency lockdown mode
func Unlock() {
	mu.Lock()
	defer mu.Unlock()
	lockdownMode = false
}
