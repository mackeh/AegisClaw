package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mackeh/AegisClaw/internal/agent"
	"github.com/mackeh/AegisClaw/internal/audit"
	"github.com/mackeh/AegisClaw/internal/config"
	"github.com/mackeh/AegisClaw/internal/policy"
	"github.com/mackeh/AegisClaw/internal/sandbox"
	"github.com/mackeh/AegisClaw/internal/scope"
	"github.com/mackeh/AegisClaw/internal/secrets"
	"github.com/mackeh/AegisClaw/internal/skill"
	"github.com/spf13/cobra"
)

var version = "0.1.0-dev"

func main() {
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
							
							if err := agent.ExecuteSkill(cmd.Context(), targetManifest, cmdName, args); err != nil {
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
			p, err := policy.LoadDefaultPolicy()
			if err != nil {
				return fmt.Errorf("failed to load policy: %w", err)
			}

			fmt.Printf("📋 Policy Version: %s\n", p.Version)
			fmt.Println("Rules:")
			for _, rule := range p.Rules {
				// Parse scope to get risk level
				s, _ := scope.Parse(rule.Scope)

				fmt.Printf("  • %-15s → %s (%s %s)\n",
					rule.Scope,
					rule.Decision,
					s.RiskLevel.Emoji(),
					s.RiskLevel.String(),
				)

				if len(rule.Constraints) > 0 {
					for k, v := range rule.Constraints {
						fmt.Printf("    └─ %s: %v\n", k, v)
					}
				}
			}
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

			fmt.Printf("🔐 Secret '%s' encryption simulated (Phase 5 MVP)\n", key)
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List stored secrets (names only)",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("🔐 Stored Secrets:")
			// List logic would go here
			fmt.Println("  (listing not implemented in MVP)")
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

			return agent.ExecuteSkill(cmd.Context(), m, cmdName, userArgs)
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

	return cmd
}