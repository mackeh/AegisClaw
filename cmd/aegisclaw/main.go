package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"encoding/json"

	"github.com/mackeh/AegisClaw/internal/agent"
	"github.com/mackeh/AegisClaw/internal/cluster"
	"github.com/mackeh/AegisClaw/internal/audit"
	"github.com/mackeh/AegisClaw/internal/config"
	"github.com/mackeh/AegisClaw/internal/doctor"
	"github.com/mackeh/AegisClaw/internal/guardrails"
	"github.com/mackeh/AegisClaw/internal/marketplace"
	"github.com/mackeh/AegisClaw/internal/mcp"
	"github.com/mackeh/AegisClaw/internal/posture"
	"github.com/mackeh/AegisClaw/internal/sandbox"
	"github.com/mackeh/AegisClaw/internal/secrets"
	"github.com/mackeh/AegisClaw/internal/server"
	"github.com/mackeh/AegisClaw/internal/simulate"
	"github.com/mackeh/AegisClaw/internal/skill"
	"github.com/mackeh/AegisClaw/internal/telemetry"
	"github.com/mackeh/AegisClaw/internal/xray"
	"github.com/spf13/cobra"
)

var version = "0.5.1"

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
	rootCmd.AddCommand(doctorCmd())
	rootCmd.AddCommand(completionCmd())
	rootCmd.AddCommand(postureCmd())
	rootCmd.AddCommand(simulateCmd())
	rootCmd.AddCommand(mcpServerCmd())
	rootCmd.AddCommand(guardrailsCmd())
	rootCmd.AddCommand(xrayCmd())
	rootCmd.AddCommand(marketplaceCmd())
	rootCmd.AddCommand(clusterCmd())

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

func doctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Diagnose AegisClaw setup and environment",
		Long:  "Runs health checks on Docker, secrets, audit logs, policy engine, and disk space.",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("🩺  AegisClaw Health Check")
			fmt.Println()

			results := doctor.RunAll()

			passed, warned, failed := 0, 0, 0
			for _, r := range results {
				var icon string
				switch r.Status {
				case doctor.StatusPass:
					icon = "✅"
					passed++
				case doctor.StatusWarn:
					icon = "⚠️ "
					warned++
				case doctor.StatusFail:
					icon = "❌"
					failed++
				}

				// Pad name to align output
				name := r.Name
				dots := strings.Repeat(".", 25-len(name))
				fmt.Printf("%s %s %s %s\n", icon, name, dots, r.Detail)

				if r.Fix != "" && r.Status != doctor.StatusPass {
					fmt.Printf("   → %s\n", r.Fix)
				}
			}

			fmt.Printf("\n%d/%d checks passed", passed, len(results))
			if warned > 0 {
				fmt.Printf(" (%d warning", warned)
				if warned > 1 {
					fmt.Print("s")
				}
				fmt.Print(")")
			}
			if failed > 0 {
				fmt.Printf(" (%d failure", failed)
				if failed > 1 {
					fmt.Print("s")
				}
				fmt.Print(")")
			}
			fmt.Println()

			if failed > 0 {
				os.Exit(1)
			}
			return nil
		},
	}
}

func completionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion scripts",
		Long: `Generate shell completion scripts for AegisClaw.

To load completions:

Bash:
  $ source <(aegisclaw completion bash)
  # Or add to ~/.bashrc:
  $ aegisclaw completion bash > /etc/bash_completion.d/aegisclaw

Zsh:
  $ aegisclaw completion zsh > "${fpath[1]}/_aegisclaw"

Fish:
  $ aegisclaw completion fish | source
  $ aegisclaw completion fish > ~/.config/fish/completions/aegisclaw.fish

PowerShell:
  PS> aegisclaw completion powershell | Out-String | Invoke-Expression
`,
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"bash", "zsh", "fish", "powershell"},
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return cmd.Root().GenBashCompletion(os.Stdout)
			case "zsh":
				return cmd.Root().GenZshCompletion(os.Stdout)
			case "fish":
				return cmd.Root().GenFishCompletion(os.Stdout, true)
			case "powershell":
				return cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
			default:
				return fmt.Errorf("unsupported shell: %s", args[0])
			}
		},
	}
}

func postureCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "posture",
		Short: "Show security posture score",
		Long:  "Evaluates your AegisClaw configuration and assigns a security grade.",
		RunE: func(cmd *cobra.Command, args []string) error {
			score, err := posture.Calculate()
			if err != nil {
				return err
			}

			fmt.Println("🛡️  AegisClaw Security Posture")
			fmt.Println()

			for _, c := range score.Categories {
				bar := renderBar(c.Points, c.Max)
				fmt.Printf("  %-12s %s %d/%d  %s\n", c.Name, bar, c.Points, c.Max, c.Detail)
			}

			fmt.Println()
			fmt.Printf("  Total: %d/%d (%d%%) — Grade: %s\n", score.Total, score.Max, score.Percentage, score.Grade)
			return nil
		},
	}
}

func renderBar(points, max int) string {
	width := 20
	filled := 0
	if max > 0 {
		filled = points * width / max
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	return "[" + bar + "]"
}

func simulateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "simulate [MANIFEST_PATH]",
		Short: "Dry-run a skill without executing it",
		Long:  "Analyzes a skill manifest and predicts behaviour, scope usage, and policy decisions.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			manifestPath := args[0]
			m, err := skill.LoadManifest(manifestPath)
			if err != nil {
				return err
			}

			report, err := simulate.Run(cmd.Context(), m)
			if err != nil {
				return err
			}

			fmt.Printf("🔮 Simulation Report: %s v%s\n", report.SkillName, report.Version)
			fmt.Printf("   Platform: %s | Image: %s\n", report.Platform, report.Image)
			fmt.Println()

			if len(report.Commands) > 0 {
				fmt.Println("   Commands:")
				for _, c := range report.Commands {
					fmt.Printf("     - %s\n", c)
				}
				fmt.Println()
			}

			if len(report.Scopes) > 0 {
				fmt.Println("   Scopes:")
				for _, s := range report.Scopes {
					risk := s.Risk
					switch risk {
					case "critical":
						risk = "🔴 critical"
					case "high":
						risk = "🟠 high"
					case "medium":
						risk = "🟡 medium"
					case "low":
						risk = "🟢 low"
					}
					fmt.Printf("     %s  [%s]\n", s.Raw, risk)
				}
				fmt.Println()
			}

			if len(report.NetworkAccess) > 0 {
				fmt.Println("   Network access:")
				for _, n := range report.NetworkAccess {
					fmt.Printf("     🌐 %s\n", n)
				}
				fmt.Println()
			}

			if len(report.FileAccess) > 0 {
				fmt.Println("   File access:")
				for _, f := range report.FileAccess {
					fmt.Printf("     📁 %s\n", f)
				}
				fmt.Println()
			}

			fmt.Printf("   Risk assessment: %s\n", strings.ToUpper(report.RiskLevel))
			fmt.Printf("   Policy decision: %s\n", report.PolicyDecision)

			if len(report.Warnings) > 0 {
				fmt.Println()
				fmt.Println("   Warnings:")
				for _, w := range report.Warnings {
					fmt.Printf("     ⚠️  %s\n", w)
				}
			}

			return nil
		},
	}
}

func mcpServerCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "mcp-server",
		Short: "Start the MCP server for AI assistant integration",
		Long: `Start a Model Context Protocol server on stdio.

This allows AI assistants like Claude Code to interact with AegisClaw.

Configure in your MCP settings:
  {
    "mcpServers": {
      "aegisclaw": {
        "command": "aegisclaw",
        "args": ["mcp-server"]
      }
    }
  }`,
		RunE: func(cmd *cobra.Command, args []string) error {
			srv := mcp.NewServer()
			return srv.Run(cmd.Context())
		},
	}
}

func guardrailsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "guardrails",
		Short: "LLM prompt safety rails",
		Long:  "Check prompts and responses against guardrail rules for injection, jailbreak, and data leakage.",
	}

	checkCmd := &cobra.Command{
		Use:   "check [text]",
		Short: "Check text against guardrail rules",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			text := strings.Join(args, " ")
			mode, _ := cmd.Flags().GetString("mode")

			engine := guardrails.NewEngine()

			var result *guardrails.Result
			switch mode {
			case "input":
				result = engine.CheckInput(text)
			case "output":
				result = engine.CheckOutput(text)
			default:
				return fmt.Errorf("mode must be 'input' or 'output'")
			}

			if result.Allowed {
				fmt.Println("   ALLOWED")
			} else {
				fmt.Println("   BLOCKED")
			}

			if len(result.Violations) > 0 {
				fmt.Printf("\n   Violations (%d):\n", len(result.Violations))
				for _, v := range result.Violations {
					fmt.Printf("     [%s] %s: %s\n", strings.ToUpper(string(v.Severity)), v.Rule, v.Message)
				}
			} else {
				fmt.Println("   No violations detected.")
			}

			if result.Sanitized != "" && result.Sanitized != text {
				fmt.Printf("\n   Sanitized output:\n   %s\n", result.Sanitized)
			}

			return nil
		},
	}
	checkCmd.Flags().String("mode", "input", "Check mode: 'input' (prompt) or 'output' (response)")

	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan text from stdin against guardrail rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			mode, _ := cmd.Flags().GetString("mode")
			engine := guardrails.NewEngine()

			scanner := bufio.NewScanner(os.Stdin)
			scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

			fmt.Fprintf(os.Stderr, "Reading from stdin (mode=%s)...\n", mode)

			var lines []string
			for scanner.Scan() {
				lines = append(lines, scanner.Text())
			}
			text := strings.Join(lines, "\n")

			var result *guardrails.Result
			switch mode {
			case "input":
				result = engine.CheckInput(text)
			case "output":
				result = engine.CheckOutput(text)
			default:
				return fmt.Errorf("mode must be 'input' or 'output'")
			}

			if result.Allowed {
				fmt.Println("ALLOWED")
			} else {
				fmt.Println("BLOCKED")
				for _, v := range result.Violations {
					fmt.Printf("  [%s] %s: %s\n", strings.ToUpper(string(v.Severity)), v.Rule, v.Message)
				}
			}

			return nil
		},
	}
	scanCmd.Flags().String("mode", "input", "Check mode: 'input' (prompt) or 'output' (response)")

	cmd.AddCommand(checkCmd)
	cmd.AddCommand(scanCmd)
	return cmd
}

func xrayCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "xray",
		Short: "Deep inspection of running skill containers",
		Long:  "Agent X-Ray mode: inspect CPU, memory, network, and processes of running AegisClaw skills.",
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all running AegisClaw containers with resource stats",
		RunE: func(cmd *cobra.Command, args []string) error {
			inspector, err := xray.NewInspector()
			if err != nil {
				return err
			}

			snapshots, err := inspector.ListAegisClaw(cmd.Context())
			if err != nil {
				return err
			}

			if len(snapshots) == 0 {
				fmt.Println("No running AegisClaw containers found.")
				fmt.Println("Hint: containers need the label 'aegisclaw.skill' to be detected.")
				return nil
			}

			for _, s := range snapshots {
				fmt.Printf("   Container: %s (%s)\n", s.ContainerName, s.ContainerID)
				fmt.Printf("     Image:   %s\n", s.Image)
				fmt.Printf("     Status:  %s\n", s.Status)
				fmt.Printf("     CPU:     %.1f%%\n", s.Resources.CPUPercent)
				fmt.Printf("     Memory:  %.1f MB / %.0f MB (%.1f%%)\n",
					s.Resources.MemoryMB, s.Resources.MemoryMax, s.Resources.MemoryPct)
				fmt.Printf("     PIDs:    %d\n", s.Resources.PIDs)
				if len(s.Network) > 0 {
					for _, n := range s.Network {
						fmt.Printf("     Net[%s]: RX %.1f KB / TX %.1f KB\n",
							n.Interface, float64(n.RxBytes)/1024, float64(n.TxBytes)/1024)
					}
				}
				fmt.Println()
			}
			return nil
		},
	}

	inspectCmd := &cobra.Command{
		Use:   "inspect [container-id]",
		Short: "Detailed inspection of a specific container",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			inspector, err := xray.NewInspector()
			if err != nil {
				return err
			}

			snap, err := inspector.Inspect(cmd.Context(), args[0])
			if err != nil {
				return err
			}

			data, _ := json.MarshalIndent(snap, "", "  ")
			fmt.Println(string(data))
			return nil
		},
	}

	cmd.AddCommand(listCmd)
	cmd.AddCommand(inspectCmd)
	return cmd
}

func marketplaceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "marketplace",
		Aliases: []string{"market", "store"},
		Short:   "Discover, search, and install skills from the marketplace",
	}

	searchCmd := &cobra.Command{
		Use:   "search [query]",
		Short: "Search the skill marketplace",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfgDir, err := config.DefaultConfigDir()
			if err != nil {
				return err
			}

			cache := marketplace.NewCache(filepath.Join(cfgDir, "marketplace"))
			idx, err := cache.Load()
			if err != nil {
				fmt.Println("No cached marketplace index. Run 'aegisclaw marketplace refresh' first.")
				return nil
			}

			query := ""
			if len(args) > 0 {
				query = strings.Join(args, " ")
			}

			sortBy, _ := cmd.Flags().GetString("sort")

			results := marketplace.Search(idx, query)
			switch sortBy {
			case "rating":
				marketplace.SortByRating(results)
			case "downloads":
				marketplace.SortByDownloads(results)
			}

			if len(results) == 0 {
				fmt.Println("No skills found.")
				return nil
			}

			fmt.Printf("Found %d skill(s):\n\n", len(results))
			for _, e := range results {
				fmt.Println(marketplace.FormatEntry(e))
				fmt.Println()
			}
			return nil
		},
	}
	searchCmd.Flags().String("sort", "rating", "Sort results by: rating, downloads")

	refreshCmd := &cobra.Command{
		Use:   "refresh",
		Short: "Refresh the marketplace index cache",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.LoadDefault()
			if err != nil {
				return err
			}
			if cfg.Registry.URL == "" {
				fmt.Println("Registry URL not configured in config.yaml.")
				fmt.Println("Set registry.url to your marketplace endpoint.")
				return nil
			}

			regIdx, err := skill.SearchRegistry(cfg.Registry.URL)
			if err != nil {
				return fmt.Errorf("fetch registry: %w", err)
			}

			// Convert to marketplace index
			var entries []marketplace.SkillEntry
			for _, s := range regIdx.Skills {
				entries = append(entries, marketplace.SkillEntry{
					Name:        s.Name,
					Version:     s.Version,
					Description: s.Description,
					Badge:       marketplace.BadgeCommunity,
					ManifestURL: s.ManifestURL,
				})
			}

			cfgDir, _ := config.DefaultConfigDir()
			cache := marketplace.NewCache(filepath.Join(cfgDir, "marketplace"))
			idx := &marketplace.Index{
				Name:   regIdx.RegistryName,
				URL:    cfg.Registry.URL,
				Skills: entries,
			}
			if err := cache.Save(idx); err != nil {
				return err
			}

			fmt.Printf("Refreshed marketplace index: %d skills cached.\n", len(entries))
			return nil
		},
	}

	infoCmd := &cobra.Command{
		Use:   "info [skill-name]",
		Short: "Show detailed info about a marketplace skill",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfgDir, err := config.DefaultConfigDir()
			if err != nil {
				return err
			}

			cache := marketplace.NewCache(filepath.Join(cfgDir, "marketplace"))
			idx, err := cache.Load()
			if err != nil {
				fmt.Println("No cached marketplace index. Run 'aegisclaw marketplace refresh' first.")
				return nil
			}

			results := marketplace.Search(idx, args[0])
			for _, e := range results {
				if e.Name == args[0] {
					data, _ := json.MarshalIndent(e, "", "  ")
					fmt.Println(string(data))
					return nil
				}
			}

			fmt.Printf("Skill '%s' not found in marketplace.\n", args[0])
			return nil
		},
	}

	cmd.AddCommand(searchCmd)
	cmd.AddCommand(refreshCmd)
	cmd.AddCommand(infoCmd)
	return cmd
}

func clusterCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cluster",
		Short: "Multi-node cluster management",
		Long:  "Manage a cluster of AegisClaw instances with centralized policy and audit aggregation.",
	}

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show cluster status",
		RunE: func(cmd *cobra.Command, args []string) error {
			nodeID, _ := cmd.Flags().GetString("node-id")
			addr, _ := cmd.Flags().GetString("address")
			role, _ := cmd.Flags().GetString("role")

			node := cluster.NewNode(nodeID, addr, cluster.NodeRole(role), version)
			status := node.Status()

			fmt.Printf("   Cluster Status\n")
			fmt.Printf("   Node:     %s (%s)\n", status.Nodes[0].ID, status.Nodes[0].Role)
			fmt.Printf("   Address:  %s\n", status.Nodes[0].Address)
			fmt.Printf("   Status:   %s\n", status.Nodes[0].Status)
			fmt.Printf("   Nodes:    %d total, %d online\n", status.NodeCount, status.OnlineNodes)

			return nil
		},
	}
	statusCmd.Flags().String("node-id", "node-1", "This node's ID")
	statusCmd.Flags().String("address", "localhost:9090", "This node's gRPC address")
	statusCmd.Flags().String("role", "leader", "Node role: leader or follower")

	joinCmd := &cobra.Command{
		Use:   "join [leader-address]",
		Short: "Join a cluster as a follower node",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			nodeID, _ := cmd.Flags().GetString("node-id")
			addr, _ := cmd.Flags().GetString("address")

			node := cluster.NewNode(nodeID, addr, cluster.RoleFollower, version)
			conn, err := node.ConnectToLeader(args[0])
			if err != nil {
				return fmt.Errorf("failed to connect to leader: %w", err)
			}
			defer conn.Close()

			fmt.Printf("   Connected to leader at %s\n", args[0])
			fmt.Printf("   Node %s registered as follower\n", nodeID)
			return nil
		},
	}
	joinCmd.Flags().String("node-id", "node-1", "This node's ID")
	joinCmd.Flags().String("address", "localhost:9091", "This node's gRPC address")

	cmd.AddCommand(statusCmd)
	cmd.AddCommand(joinCmd)
	return cmd
}
