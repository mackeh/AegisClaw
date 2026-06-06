package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/mackeh/AegisClaw/internal/audit"
	"github.com/mackeh/AegisClaw/internal/config"
	"github.com/mackeh/AegisClaw/internal/harness"
	"github.com/mackeh/AegisClaw/internal/harness/adapters/generic"
	"github.com/mackeh/AegisClaw/internal/harness/sandboxlauncher"
	"github.com/mackeh/AegisClaw/internal/secrets"
	"github.com/spf13/cobra"
)

func defaultStr(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// harnessRegistry builds the adapter registry. Adapters are registered here (in
// the CLI) so the dependency direction stays one-way: adapter packages import
// internal/harness, never the reverse.
func harnessRegistry() *harness.Registry {
	reg := harness.NewRegistry()
	reg.Register(generic.New())
	return reg
}

func harnessCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "harness",
		Short: "Launch an AI agent inside the AegisClaw security envelope",
		Long: `Run an autonomous agent (OpenClaw, Hermes, or any other) with AegisClaw's
enforcement planes wired around it. Phase 1 forces a filtering egress proxy and
injects scoped, ephemeral secrets, recording the lifecycle to the audit log.`,
	}

	var agentName string
	var workDir string
	var image string
	var runtime string

	runCmd := &cobra.Command{
		Use:   "run -- [COMMAND...]",
		Short: "Launch an agent process with egress filtering and scoped secrets enforced",
		Long: `Launch an agent with AegisClaw's enforcement planes wired around it.

By default the agent runs as a host subprocess pointed at a filtering egress
proxy. Pass --image to run the agent INSIDE a hardened sandbox container
(read-only rootfs, dropped capabilities, no-new-privileges, resource limits),
optionally selecting a stronger runtime with --runtime gvisor.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfgDir, err := config.DefaultConfigDir()
			if err != nil {
				return err
			}

			reg := harnessRegistry()
			adapter, err := reg.Get(agentName)
			if err != nil {
				return err
			}

			// Audit logger (best-effort: a missing config dir shouldn't block).
			logger, err := audit.NewLogger(filepath.Join(cfgDir, "audit", "audit.log"))
			if err != nil {
				return fmt.Errorf("failed to open audit log: %w", err)
			}
			defer logger.Close()

			// Egress allowlist comes from config (default-deny tightening lands
			// with the dedicated egress plane). A missing config is non-fatal.
			var allowlist []string
			if cfg, lerr := config.LoadDefault(); lerr == nil && cfg != nil {
				allowlist = cfg.Network.Allowlist
			}

			sup := &harness.Supervisor{
				ConfigDir:      cfgDir,
				Logger:         logger,
				Secrets:        secrets.NewManager(filepath.Join(cfgDir, "secrets")),
				AllowedDomains: allowlist,
				WorkDir:        workDir,
				Image:          image,
			}

			mode := "host subprocess"
			if image != "" {
				sup.Launcher = sandboxlauncher.New(runtime)
				mode = fmt.Sprintf("sandbox (image=%s, runtime=%s)", image, defaultStr(runtime, "docker"))
			}

			fmt.Printf("🛡️  Launching agent %q inside the AegisClaw envelope [%s]...\n", adapter.Name(), mode)
			code, err := sup.Run(cmd.Context(), adapter, args, os.Stdout, os.Stderr)
			if err != nil {
				return err
			}
			fmt.Printf("🏁 Agent exited (code %d)\n", code)
			if code != 0 {
				os.Exit(code)
			}
			return nil
		},
	}
	runCmd.Flags().StringVar(&agentName, "agent", "generic", "agent adapter to use")
	runCmd.Flags().StringVar(&workDir, "workdir", "", "working directory for the agent (default: current directory)")
	runCmd.Flags().StringVar(&image, "image", "", "run the agent inside a sandbox container using this image")
	runCmd.Flags().StringVar(&runtime, "runtime", "", "sandbox runtime when --image is set: docker, gvisor, kata, firecracker")
	cmd.AddCommand(runCmd)

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List available agent adapters",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("🔌 Available agent adapters:")
			for _, n := range harnessRegistry().Names() {
				fmt.Printf("   • %s\n", n)
			}
			return nil
		},
	})

	return cmd
}
