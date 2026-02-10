package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mackeh/AegisClaw/internal/agent"
	"github.com/mackeh/AegisClaw/internal/audit"
	"github.com/mackeh/AegisClaw/internal/config"
	"github.com/mackeh/AegisClaw/internal/sandbox"
	"github.com/mackeh/AegisClaw/internal/secrets"
	"github.com/mackeh/AegisClaw/internal/server"
	"github.com/mackeh/AegisClaw/internal/skill"
	"github.com/mackeh/AegisClaw/internal/telemetry"
	"github.com/spf13/cobra"
)

var version = "0.1.0-dev"

func main() {
	// Setup Telemetry
	cfg, _ := config.LoadDefault()
	var cleanup func(context.Context) error
	
	if cfg != nil && cfg.Telemetry.Enabled {
		cfgDir, _ := config.DefaultConfigDir()
		tracePath := filepath.Join(cfgDir, "traces.json")
		f, err := os.OpenFile(tracePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err == nil {
			// Intentionally ignoring error for now to keep CLI clean
			cleanup, _ = telemetry.Setup(context.Background(), "aegisclaw", version, true, f)
		} else {
			cleanup, _ = telemetry.Setup(context.Background(), "aegisclaw", version, false, nil)
		}
	} else {
		cleanup, _ = telemetry.Setup(context.Background(), "aegisclaw", version, false, nil)
	}
	defer cleanup(context.Background())

	rootCmd := &cobra.Command{
		Use:   "aegisclaw",
		Short: "Secure-by-default runtime for AI agents",
		Long: `AegisClaw is a security envelope for personal AI agents.
It provides sandboxed execution, capability-based permissions,
human-in-the-loop approvals, encrypted secrets, and tamper-evident audit logging.`,
		Version: version,
	}

	rootCmd.AddCommand(initCmd())
	rootCmd.AddCommand(runCmd())
	rootCmd.AddCommand(policyCmd())
	rootCmd.AddCommand(secretsCmd())
	rootCmd.AddCommand(logsCmd())
	rootCmd.AddCommand(sandboxCmd())
	rootCmd.AddCommand(skillsCmd())
	rootCmd.AddCommand(serveCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func initCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Initialize AegisClaw configuration",
		Long:  "Creates the ~/.aegisclaw directory with default configuration files.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInit()
		},
	}
}

func runCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "run",
		Short: "Start the agent runtime",
		Long:  "Launches the AegisClaw runtime with the configured agent and policies.",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("🦅 AegisClaw runtime starting...")

			cfgDir, err := config.DefaultConfigDir()
			if err != nil {
				return err
			}

			// Load skills
			skillsDir := filepath.Join(cfgDir, "skills")
			manifests, _ := skill.ListSkills(skillsDir)
			localManifests, _ := skill.ListSkills("skills")
			manifests = append(manifests, localManifests...)

			fmt.Printf("🧩 Loaded %d skills\n", len(manifests))
			fmt.Println("🤖 Agent is ready. Type 'help' for commands or 'exit' to quit.")

			reader := bufio.NewReader(os.Stdin)

			// Simple REPL for now
			for {
				fmt.Print("> ")
				input, _ := reader.ReadString('\n')
				input = strings.TrimSpace(input)

				switch input {
				case "exit", "quit":
					fmt.Println("👋 Goodbye!")
					return nil
				case "clear":
					fmt.Print("\033[H\033[2J")
				case "list", "skills":
					fmt.Println("Installed skills:")
					for _, m := range manifests {
						fmt.Printf("  • %s\n", m.Name)
					}
				case "help":
					fmt.Println("Available commands:")
					fmt.Println("  list, skills    List installed skills")
					fmt.Println("  [skill] [cmd]   Run a skill command (e.g., 'hello-world hello')")
					fmt.Println("  clear           Clear the screen")
					fmt.Println("  exit, quit      Exit the runtime")
				case "":
					continue
				default:
					// Try to parse as skill execution
					parts := strings.Fields(input)
					if len(parts) > 0 {
						skillName := parts[0]

						// Find matching manifest
						var targetManifest *skill.Manifest
						for _, m := range manifests {
							if m.Name == skillName {
								targetManifest = m
								break
							}
						}

						if targetManifest != nil {
							if len(parts) < 2 {
								fmt.Printf("❌ Usage: %s [command] [args...]\n", skillName)
								continue
							}
							cmdName := parts[1]
							args := parts[2:]

							if _, err := agent.ExecuteSkill(cmd.Context(), targetManifest, cmdName, args); err != nil {
								fmt.Printf("❌ Execution failed: %v\n", err)
							}
						} else {
							fmt.Printf("❓ Unknown command or skill: %s\n", skillName)
						}
					}
				}
			}
		},
	}
}

func policyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Manage security policies",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List current policy rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfgDir, err := config.DefaultConfigDir()
			if err != nil {
				return err
			}
			policyPath := filepath.Join(cfgDir, "policy.rego")

			data, err := os.ReadFile(policyPath)
			if err != nil {
				if os.IsNotExist(err) {
					fmt.Println("⚠️  No policy file found at", policyPath)
					return nil
				}
				return fmt.Errorf("failed to read policy file: %w", err)
			}

			fmt.Printf("📋 Policy File: %s\n", policyPath)
			fmt.Println("---")
			fmt.Println(string(data))
			fmt.Println("---")
			return nil
		},
	})

	return cmd
}

func secretsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secrets",
		Short: "Manage encrypted secrets",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "init",
		Short: "Initialize secrets encryption keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfgDir, err := config.DefaultConfigDir()
			if err != nil {
				return err
			}

			// Create secrets directory if not exists
			secretsDir := filepath.Join(cfgDir, "secrets")
			if err := os.MkdirAll(secretsDir, 0700); err != nil {
				return fmt.Errorf("failed to create secrets dir: %w", err)
			}

			mgr := secrets.NewManager(secretsDir)
			pubKey, err := mgr.Init()
			if err != nil {
				return err
			}

			fmt.Println("🔐 Secrets initialized!")
			fmt.Printf("🔑 Public Key: %s\n", pubKey)
			fmt.Println("⚠️  (Save this key safe!)")
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "set [KEY] [VALUE]",
		Short: "Set an encrypted secret",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			key := args[0]
			val := args[1]

			cfgDir, err := config.DefaultConfigDir()
			if err != nil {
				return err
			}

			secretsDir := filepath.Join(cfgDir, "secrets")
			mgr := secrets.NewManager(secretsDir)

			if err := mgr.Set(key, val); err != nil {
				return err
			}

			fmt.Printf("🔐 Secret '%s' encrypted and saved.\n", key)
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List stored secrets (names only)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfgDir, err := config.DefaultConfigDir()
			if err != nil {
				return err
			}

			secretsDir := filepath.Join(cfgDir, "secrets")
			mgr := secrets.NewManager(secretsDir)

			keys, err := mgr.List()
			if err != nil {
				return err
			}

			if len(keys) == 0 {
				fmt.Println("🔐 No secrets stored.")
				return nil
			}

			fmt.Println("🔐 Stored Secrets:")
			for _, k := range keys {
				fmt.Printf("  • %s\n", k)
			}
			return nil
		},
	})

	return cmd
}

func logsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "logs",
		Short: "View audit logs",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfgDir, err := config.DefaultConfigDir()
			if err != nil {
				return err
			}
			logPath := filepath.Join(cfgDir, "audit", "audit.log")

			entries, err := audit.ReadAll(logPath)
			if err != nil {
				return err
			}

			if len(entries) == 0 {
				fmt.Println("📜 Audit Log (empty)")
				return nil
			}

			fmt.Println("📜 Audit Log:")
			for _, e := range entries {
				fmt.Printf("[%s] %s by %s (%s) → %s\n",
					e.Timestamp.Format(time.RFC3339),
					e.Action,
					e.Actor,
					e.Scopes,
					e.Decision,
				)
			}
			return nil
		},
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "verify",
		Short: "Verify audit log integrity (hash chain)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfgDir, err := config.DefaultConfigDir()
			if err != nil {
				return err
			}
			logPath := filepath.Join(cfgDir, "audit", "audit.log")

			fmt.Println("🕵️  Verifying audit log integrity...")
			valid, err := audit.Verify(logPath)
			if err != nil {
				fmt.Printf("❌ Verification FAILED: %v\n", err)
				return nil // Don't exit with error to show message
			}

			if valid {
				fmt.Println("✅ Log integrity verified. Hash chain is unbroken.")
			} else {
				fmt.Println("❌ Log integrity check returned false.")
			}
			return nil
		},
	})

	return cmd
}

func sandboxCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sandbox",
		Short: "Manage and test sandbox execution",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "run-sandbox [IMAGE] [COMMAND]",
		Short: "Run a command in the hardened sandbox",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			image := args[0]
			command := args[1:]

			fmt.Printf("🐳 Starting hardened sandbox execution...\n")
			fmt.Printf("   Image: %s\n", image)
			fmt.Printf("   Command: %v\n", command)

			exec, err := sandbox.NewDockerExecutor()
			if err != nil {
				return fmt.Errorf("failed to initialize docker executor: %w", err)
			}

			// Capture output
			ctx := cmd.Context()
			result, err := exec.Run(ctx, sandbox.Config{
				Image:   image,
				Command: command,
				Network: false, // Default deny
			})
			if err != nil {
				return fmt.Errorf("execution failed: %w", err)
			}

			fmt.Printf("✅ Execution complete (exit code %d)\n", result.ExitCode)
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "run-skill [MANIFEST_PATH] [COMMAND_NAME] [ARGS...]",
		Short: "Run a named command from a skill manifest",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			manifestPath := args[0]
			cmdName := args[1]
			userArgs := args[2:]

			// 1. Load Manifest
			m, err := skill.LoadManifest(manifestPath)
			if err != nil {
				return err
			}

			if _, err := agent.ExecuteSkill(cmd.Context(), m, cmdName, userArgs); err != nil {
				return err
			}
			return nil
		},
	})

	return cmd
}

func skillsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "skills",
		Short: "Manage agent skills",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List installed skills",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfgDir, err := config.DefaultConfigDir()
			if err != nil {
				return err
			}

			skillsDir := filepath.Join(cfgDir, "skills")

			// Also check local skills directory if it exists
			manifests, _ := skill.ListSkills(skillsDir)

			localManifests, _ := skill.ListSkills("skills")
			manifests = append(manifests, localManifests...)

			if len(manifests) == 0 {
				fmt.Println("📭 No skills installed.")
				return nil
			}

			fmt.Println("🧩 Installed Skills:")
			for _, m := range manifests {
				fmt.Printf("  • %-15s v%-8s %s\n", m.Name, m.Version, m.Description)
				for name, c := range m.Commands {
					fmt.Printf("    └─ %s: %v\n", name, c.Args)
				}
			}
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "search [QUERY]",
		Short: "Search for skills in the registry",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.LoadDefault()
			if err != nil {
				return fmt.Errorf("failed to load configuration (run 'init' first): %w", err)
			}

			if cfg.Registry.URL == "" {
				fmt.Println("⚠️  No registry URL configured. Please update ~/.aegisclaw/config.yaml")
				return nil
			}

			fmt.Printf("🔍 Searching registry: %s\n", cfg.Registry.URL)
			index, err := skill.SearchRegistry(cfg.Registry.URL)
			if err != nil {
				return err
			}

			query := ""
			if len(args) > 0 {
				query = strings.ToLower(args[0])
			}

			fmt.Printf("🧩 Available Skills in '%s':\n", index.RegistryName)
			found := false
			for _, s := range index.Skills {
				if query == "" || strings.Contains(strings.ToLower(s.Name), query) || strings.Contains(strings.ToLower(s.Description), query) {
					fmt.Printf("  • %-15s v%-8s %s\n", s.Name, s.Version, s.Description)
					found = true
				}
			}

			if !found {
				fmt.Println("  (No skills matched your search)")
			}

			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "add [SKILL_NAME]",
		Short: "Install a signed skill from the registry",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			skillName := args[0]

			cfg, err := config.LoadDefault()
			if err != nil {
				return fmt.Errorf("failed to load configuration (run 'init' first): %w", err)
			}

			if cfg.Registry.URL == "" {
				return fmt.Errorf("no registry URL configured")
			}

			cfgDir, _ := config.DefaultConfigDir()
			skillsDir := filepath.Join(cfgDir, "skills")

			fmt.Printf("📥 Installing skill '%s'...\n", skillName)
			return skill.InstallSkill(skillName, skillsDir, cfg.Registry.URL, cfg.Registry.TrustKeys)
		},
	})

	return cmd
}
func serveCmd() *cobra.Command {
	var port int
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the AegisClaw API server",
		RunE: func(cmd *cobra.Command, args []string) error {
			s := server.NewServer(port)
			return s.Start()
		},
	}

	cmd.Flags().IntVarP(&port, "port", "p", 8080, "Port to listen on")
	return cmd
}
