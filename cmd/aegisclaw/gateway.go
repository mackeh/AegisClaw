package main

import (
	"fmt"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/mackeh/AegisClaw/internal/approval"
	"github.com/mackeh/AegisClaw/internal/audit"
	"github.com/mackeh/AegisClaw/internal/config"
	"github.com/mackeh/AegisClaw/internal/llmproxy"
	"github.com/mackeh/AegisClaw/internal/mcp"
	"github.com/mackeh/AegisClaw/internal/policy"
	"github.com/spf13/cobra"
)

func gatewayCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gateway",
		Short: "Inline brokers that sit between an agent and its tools/services",
	}

	var rateLimit int
	mcpCmd := &cobra.Command{
		Use:   "mcp -- [SERVER_COMMAND...]",
		Short: "Proxy an MCP server, enforcing policy, approval, guardrails, and tool-description pinning on every tool call",
		Long: `Run AegisClaw as an inline MCP gateway. The agent points its MCP client at
AegisClaw (stdio); AegisClaw forwards vetted tool calls to the real downstream
MCP server given after '--'. Every call is checked against policy, persistent
approvals, and guardrails (arguments and responses), tool descriptions are
hash-pinned to detect tool-poisoning, and the whole session is recorded to the
tamper-evident MCP audit log.

Example:
  aegisclaw gateway mcp -- npx -y @modelcontextprotocol/server-filesystem /tmp`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			cfgDir, err := config.DefaultConfigDir()
			if err != nil {
				return err
			}

			down, err := mcp.NewStdioDownstream(ctx, args[0], args[1:]...)
			if err != nil {
				return err
			}
			defer down.Close()

			gw := mcp.NewGateway(down)
			if rateLimit != 0 {
				gw.SetRateLimit(rateLimit)
			}

			if engine, perr := policy.LoadDefaultPolicy(ctx); perr == nil {
				gw.Policy = engine
			} else {
				return fmt.Errorf("failed to load policy: %w", perr)
			}

			if logger, lerr := audit.NewLogger(filepath.Join(cfgDir, "audit", "mcp.log")); lerr == nil {
				gw.Logger = logger
				defer logger.Close()
			}

			if pins, perr := mcp.NewPinStore(filepath.Join(cfgDir, "mcp", "pins.json")); perr == nil {
				gw.Pins = pins
			}

			if store, serr := approval.NewStore(); serr == nil {
				gw.Approved = func(scopeStr string) bool { return store.Check(scopeStr) == "always" }
			}

			return gw.Run(ctx)
		},
	}
	mcpCmd.Flags().IntVar(&rateLimit, "rate-limit", 0, "max tool calls per minute (0 = default)")
	cmd.AddCommand(mcpCmd)

	cmd.AddCommand(pinsCmd())
	cmd.AddCommand(llmGatewayCmd())
	return cmd
}

func llmGatewayCmd() *cobra.Command {
	var (
		upstream      string
		mode          string
		maxTokens     int
		maxCost       float64
		maxRequests   int
		loopThreshold int
	)
	cmd := &cobra.Command{
		Use:   "llm",
		Short: "Proxy an LLM provider, enforcing guardrails, secret redaction, and token/cost/loop budgets",
		Long: `Run AegisClaw as an inline LLM proxy in front of an OpenAI/Anthropic-compatible
provider. Point your agent's base URL at the address printed on startup; every
prompt and response is scanned by the guardrails engine, secrets are scrubbed
from responses, per-session token/cost/request budgets are enforced, runaway
loops are detected, and each call is recorded to the audit log.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfgDir, err := config.DefaultConfigDir()
			if err != nil {
				return err
			}
			logger, lerr := audit.NewLogger(filepath.Join(cfgDir, "audit", "audit.log"))
			if lerr != nil {
				return fmt.Errorf("failed to open audit log: %w", lerr)
			}
			defer logger.Close()

			p := llmproxy.New(upstream, llmproxy.Options{
				Mode:          mode,
				Logger:        logger,
				Budget:        &llmproxy.Budget{MaxTokens: maxTokens, MaxCostUSD: maxCost, MaxRequests: maxRequests},
				LoopThreshold: loopThreshold,
			})
			url, err := p.Start()
			if err != nil {
				return err
			}
			defer p.Stop()

			fmt.Printf("🧠 LLM proxy listening on %s → %s (mode=%s)\n", url, upstream, mode)
			fmt.Printf("   Point your agent at it, e.g. OPENAI_BASE_URL=%s/v1  or  ANTHROPIC_BASE_URL=%s\n", url, url)

			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			<-ctx.Done()
			fmt.Println("\n👋 LLM proxy shutting down.")
			return nil
		},
	}
	cmd.Flags().StringVar(&upstream, "upstream", "https://api.openai.com", "provider base URL (scheme://host)")
	cmd.Flags().StringVar(&mode, "mode", "warn", "guardrail mode: off, warn, or block")
	cmd.Flags().IntVar(&maxTokens, "max-tokens", 0, "per-session token budget (0 = unlimited)")
	cmd.Flags().Float64Var(&maxCost, "max-cost", 0, "per-session cost budget in USD (0 = unlimited)")
	cmd.Flags().IntVar(&maxRequests, "max-requests", 0, "per-session request budget (0 = unlimited)")
	cmd.Flags().IntVar(&loopThreshold, "loop-threshold", 0, "block after N identical requests in 60s (0 = off)")
	return cmd
}

func pinsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pins",
		Short: "Manage MCP tool-description pins (tool-poisoning defense)",
	}

	pinsPath := func() (string, error) {
		cfgDir, err := config.DefaultConfigDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(cfgDir, "mcp", "pins.json"), nil
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List pinned tools",
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := pinsPath()
			if err != nil {
				return err
			}
			pins, err := mcp.NewPinStore(path)
			if err != nil {
				return err
			}
			names := pins.Names()
			if len(names) == 0 {
				fmt.Println("📌 No MCP tool pins recorded yet.")
				return nil
			}
			fmt.Println("📌 Pinned MCP tools:")
			for _, n := range names {
				h, _ := pins.Get(n)
				fmt.Printf("   • %s  (%s…)\n", n, h[:min(12, len(h))])
			}
			return nil
		},
	})

	var all bool
	resetCmd := &cobra.Command{
		Use:   "reset [TOOL]",
		Short: "Re-approve a changed tool by removing its pin (re-pins on next use)",
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := pinsPath()
			if err != nil {
				return err
			}
			pins, err := mcp.NewPinStore(path)
			if err != nil {
				return err
			}
			if all {
				for _, n := range pins.Names() {
					pins.Remove(n)
				}
				fmt.Println("✅ Cleared all MCP tool pins.")
			} else if len(args) == 1 {
				pins.Remove(args[0])
				fmt.Printf("✅ Cleared pin for %q; it will be re-pinned on next use.\n", args[0])
			} else {
				return fmt.Errorf("specify a TOOL name or --all")
			}
			return pins.Save()
		},
	}
	resetCmd.Flags().BoolVar(&all, "all", false, "reset every pin")
	cmd.AddCommand(resetCmd)

	return cmd
}
