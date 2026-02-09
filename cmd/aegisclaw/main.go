package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/mackeh/AegisClaw/internal/approval"
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
			fmt.Println("⚠️  Runtime not yet implemented. Coming in Phase 3.")
			return nil
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

	cmd.AddCommand(&cobra.Command{
		Use:   "example-request",
		Short: "Simulate a permission request (demo)",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Create a dummy high-risk request
			req := scope.ScopeRequest{
				RequestedBy: "WebBrowserSkill",
				Reason:      "Needs to execute curl to download a file",
				Scopes: []scope.Scope{
					scope.ShellExec,
					{Name: "files.write", Resource: "/tmp/download.zip", RiskLevel: scope.RiskHigh},
				},
			}

			fmt.Println("🤖 Skill is requesting permissions...")
			
			// Check if already approved (in real implementation, this would be in policy engine)
			store, err := approval.NewStore()
			if err != nil {
				return err
			}
			
			// Simple check for first scope
			if decision := store.Check("shell.exec"); decision == "always" {
				fmt.Println("✅ Auto-approved based on previous 'always' decision.")
				return nil
			}

			// Prompt user
			decision, err := approval.RequestApproval(req)
			if err != nil {
				return err
			}

			fmt.Printf("User decision: %s\n", decision)

			if decision == "always" {
				if err := store.Grant("shell.exec", "always"); err != nil {
					fmt.Printf("Failed to save approval: %v\n", err)
				}
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
	
				// 2. Find Command
				skillCmd, ok := m.Commands[cmdName]
				if !ok {
					return fmt.Errorf("command '%s' not found in skill '%s'", cmdName, m.Name)
				}
	
				// 3. Prepare Scopes
				var reqScopes []scope.Scope
				needsNetwork := false
				for _, sStr := range m.Scopes {
					s, _ := scope.Parse(sStr)
					reqScopes = append(reqScopes, s)
					if s.Name == "http.request" || s.Name == "email.send" {
						needsNetwork = true
					}
				}
	
				req := scope.ScopeRequest{
					RequestedBy: m.Name,
					Reason:      fmt.Sprintf("Executing action '%s'", cmdName),
					Scopes:      reqScopes,
				}
	
				// 4. Load Policy & Evaluate
				p, err := policy.LoadDefaultPolicy()
				if err != nil {
					return fmt.Errorf("failed to load policy: %w", err)
				}
				engine := policy.NewEngine(p)
				decision, riskyScopes := engine.EvaluateRequest(req)
	
				finalDecision := "deny"
				
				// 5. Enforce Decision
				switch decision {
				case policy.Deny:
					fmt.Println("❌ Policy DENIED this action.")
					return fmt.Errorf("policy denied action")
				
				case policy.RequireApproval:
					// Check persistent approvals
					store, err := approval.NewStore()
					if err != nil {
						return err
					}
	
					allApproved := true
					for _, s := range riskyScopes {
						if store.Check(s.String()) != "always" {
							allApproved = false
							break
						}
					}
	
					if allApproved {
						finalDecision = "allow"
						fmt.Println("✅ Auto-approved based on previous settings.")
					} else {
						// Prompt User
						userDec, err := approval.RequestApproval(req)
						if err != nil {
							return err
						}
						
						if userDec == "deny" {
							fmt.Println("❌ User denied the request.")
							return fmt.Errorf("user denied request")
						}
						
						finalDecision = "allow"
						if userDec == "always" {
							for _, s := range riskyScopes {
								_ = store.Grant(s.String(), "always")
							}
							fmt.Println("💾 Approval saved for future requests.")
						}
					}
	
				case policy.Allow:
					finalDecision = "allow"
				}
	
				// 6. Audit Log (Pre-execution)
				cfgDir, _ := config.DefaultConfigDir()
				auditPath := filepath.Join(cfgDir, "audit", "audit.log")
				logger, err := audit.NewLogger(auditPath)
				if err == nil {
					// Log the attempt
					_ = logger.Log("skill.exec", reqScopes, finalDecision, m.Name, map[string]any{
						"command": cmdName,
						"image":   m.Image,
					})
				}
	
				if finalDecision != "allow" {
					return fmt.Errorf("execution blocked")
				}
	
				// 7. Execute
				finalArgs := append(skillCmd.Args, userArgs...)
				fmt.Printf("🚀 Running skill: %s\n", m.Name)
				
				exec, err := sandbox.NewDockerExecutor()
				if err != nil {
					return fmt.Errorf("failed to initialize executor: %w", err)
				}
	
				ctx := cmd.Context()
				result, err := exec.Run(ctx, sandbox.Config{
					Image:   m.Image,
					Command: finalArgs,
					Network: needsNetwork,
				})
				if err != nil {
					return fmt.Errorf("execution failed: %w", err)
				}
	
				fmt.Printf("✅ Skill finished (exit code %d)\n", result.ExitCode)
				return nil
			},
		})
	return cmd
}
