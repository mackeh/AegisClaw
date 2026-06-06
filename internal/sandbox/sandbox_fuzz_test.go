package sandbox

import (
	"testing"
)

func FuzzConfigValidation(f *testing.F) {
	// Seed corpus
	f.Add("alpine:latest", "echo hello", "/tmp", true)
	f.Add("ubuntu:22.04", "rm -rf /", "/root", false)

	f.Fuzz(func(t *testing.T, image, cmdStr, workDir string, network bool) {
		cfg := Config{
			Image:   image,
			Command: []string{cmdStr},
			WorkDir: workDir,
			Network: network,
		}

		if len(cfg.Command) == 0 {
			return
		}
		
		if cfg.Image == "" {
			return
		}

		_, err := NewExecutor(RuntimeDocker)
		if err != nil {
			return
		}
	})
}
