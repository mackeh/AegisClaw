# AegisClaw — Detailed Build Process

> Implementation guide for Roadmap v0.4.x–v0.6.x and Long-Term Vision

---

## Table of Contents

1. [v0.4.x: Usability & Developer Experience](#v04x-usability--developer-experience)
2. [v0.5.x: Advanced Security](#v05x-advanced-security)
3. [v0.6.x: Woo Factor & Ecosystem](#v06x-woo-factor--ecosystem)
4. [Long-Term Vision](#long-term-vision)
5. [Infrastructure & DevOps Requirements](#infrastructure--devops-requirements)
6. [Dependency Map](#dependency-map)

---

## v0.4.x: Usability & Developer Experience

### 4.1 — Package Manager Distribution

**Goal:** Install AegisClaw without cloning the repo.

**Steps:**

1. **GoReleaser setup** (`.goreleaser.yaml` already exists — extend it):
   ```yaml
   builds:
     - main: ./cmd/aegisclaw
       goos: [linux, darwin, windows]
       goarch: [amd64, arm64]
       ldflags:
         - -s -w -X main.version={{.Version}}
   
   archives:
     - format: tar.gz
       format_overrides:
         - goos: windows
           format: zip
   
   brews:
     - repository:
         owner: mackeh
         name: homebrew-aegisclaw
       homepage: https://github.com/mackeh/AegisClaw
       description: "Secure-by-default runtime for AI agents"
   
   checksum:
     name_template: 'checksums.txt'
   ```

2. **GitHub Actions release workflow:**
   ```yaml
   on:
     push:
       tags: ['v*']
   jobs:
     release:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
         - uses: actions/setup-go@v5
           with: { go-version: '1.22' }
         - uses: goreleaser/goreleaser-action@v5
           with: { args: release --clean }
           env: { GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }} }
   ```

3. **Homebrew tap** — auto-updated by GoReleaser on each release

4. **`go install` support:**
   ```bash
   go install github.com/mackeh/AegisClaw/cmd/aegisclaw@latest
   ```
   - Ensure module path is clean in `go.mod`
   - Tag releases with semver (`v0.4.0`)

5. **Install script:**
   ```bash
   curl -fsSL https://raw.githubusercontent.com/mackeh/AegisClaw/main/install.sh | bash
   ```
   - Detect OS/arch, download correct binary, move to `/usr/local/bin`

**Estimated effort:** 1–2 weeks  
**Dependencies:** GoReleaser, GitHub Actions  
**Key files:** `.goreleaser.yaml`, `.github/workflows/release.yml`, `install.sh`

---

### 4.2 — Interactive Init Wizard

**Goal:** Guided first-run setup that configures AegisClaw for the user's environment.

**Steps:**

1. **Add `survey` or `bubbletea` Go library** for interactive prompts:
   ```bash
   go get github.com/charmbracelet/bubbletea
   go get github.com/charmbracelet/huh  # form library
   ```

2. **Implement wizard flow:**
   ```
   $ aegisclaw init
   
   🛡️  AegisClaw Setup
   
   Detecting environment...
   ✓ Docker: found (v24.0.7)
   ✓ gVisor: not found (optional)
   ✗ OpenClaw: not configured
   
   ? Default sandbox runtime?
     ❯ Docker (recommended)
       gVisor (requires runsc)
   
   ? Policy strictness?
     ❯ Standard (allow known-safe, approve high-risk)
       Strict (deny-by-default, approve everything)
       Permissive (allow most, log everything)
   
   ? Enable secret encryption?
     ❯ Yes (recommended)
       No
   
   ✅ Created ~/.aegisclaw/config.yaml
   ✅ Created ~/.aegisclaw/policies/default.rego
   ✅ Initialized secret store
   
   Next: Run `aegisclaw secrets set OPENAI_API_KEY <key>` to add your first secret.
   ```

3. **Auto-detect capabilities:**
   ```go
   func detectEnvironment() Environment {
       env := Environment{}
       env.DockerAvailable = exec.Command("docker", "info").Run() == nil
       env.GVisorAvailable = exec.Command("runsc", "--version").Run() == nil
       env.OpenClawEndpoint = os.Getenv("OPENCLAW_ENDPOINT")
       return env
   }
   ```

4. **Generate config files** based on answers — `config.yaml`, default Rego policy, adapter configs

**Estimated effort:** 2 weeks  
**Dependencies:** `charmbracelet/huh` or `charmbracelet/bubbletea`  
**Key files:** `cmd/aegisclaw/cmd_init.go`, `internal/wizard/`

---

### 4.3 — Starter Skill Packs

**Goal:** Pre-built, signed skills that work out-of-the-box.

**Steps:**

1. **Create 3–5 starter skills:**
   - **file-organiser**: Sorts files in a directory by type/date (scopes: `files.read:/tmp`, `files.write:/tmp`)
   - **web-search**: Fetches search results from a public API (scopes: `net.outbound:api.duckduckgo.com`)
   - **code-runner**: Executes a Python/JS snippet in a sandboxed container (scopes: `shell.exec`)
   - **summariser**: Sends text to an LLM API and returns a summary (scopes: `net.outbound:api.openai.com`)
   - **git-stats**: Analyses a git repo and reports contributor stats (scopes: `files.read:`, `shell.exec:git`)

2. **Package as Docker images:**
   ```dockerfile
   # skills/file-organiser/Dockerfile
   FROM alpine:3.19
   RUN apk add --no-cache python3
   COPY organise.py /app/
   ENTRYPOINT ["python3", "/app/organise.py"]
   ```

3. **Create signed manifests:**
   ```yaml
   # skills/file-organiser/manifest.yaml
   name: file-organiser
   version: 1.0.0
   image: ghcr.io/mackeh/aegisclaw-skills/file-organiser:1.0.0
   platform: docker
   scopes:
     - files.read:/tmp/input
     - files.write:/tmp/output
   signature: "ed25519:..."
   ```

4. **Publish images** to `ghcr.io/mackeh/aegisclaw-skills/`

5. **Bundle manifests** in the default `~/.aegisclaw/skills/` directory during `aegisclaw init`

6. **Sign each skill** with the project's signing key

**Estimated effort:** 2–3 weeks  
**Dependencies:** Docker, GitHub Container Registry  
**Key files:** `skills/*/`, `skills/*/Dockerfile`, `skills/*/manifest.yaml`

---

### 4.4 — `aegisclaw doctor`

**Goal:** Single command to diagnose the entire setup.

**Steps:**

1. **Implement health checks:**
   ```go
   type HealthCheck struct {
       Name    string
       Check   func() error
       Fix     string // suggested fix if check fails
   }
   
   var checks = []HealthCheck{
       {"Docker daemon", checkDocker, "Install Docker: https://docs.docker.com/get-docker/"},
       {"gVisor runtime", checkGVisor, "Optional: https://gvisor.dev/docs/user_guide/install/"},
       {"Secret store", checkSecrets, "Run: aegisclaw secrets init"},
       {"Audit log integrity", checkAuditLog, "Run: aegisclaw logs verify"},
       {"OpenClaw adapter", checkAdapter, "Configure ~/.aegisclaw/adapters/openclaw.yaml"},
       {"Policy engine", checkPolicy, "Ensure default.rego exists in ~/.aegisclaw/policies/"},
       {"Disk space", checkDiskSpace, "Free up space in ~/.aegisclaw/"},
   }
   ```

2. **Output format:**
   ```
   $ aegisclaw doctor
   
   🩺  AegisClaw Health Check
   
   ✅ Docker daemon ............. running (v24.0.7)
   ✅ Secret store .............. initialized (3 secrets)
   ✅ Audit log ................. valid (847 entries, chain intact)
   ⚠️  gVisor runtime ........... not installed (optional)
   ❌ OpenClaw adapter .......... not configured
      → Configure ~/.aegisclaw/adapters/openclaw.yaml
   ✅ Policy engine ............. loaded (default.rego)
   ✅ Disk space ................ 4.2 GB free
   
   6/7 checks passed (1 warning, 1 failure)
   ```

3. **Exit code** — non-zero if any required check fails (for CI usage)

**Estimated effort:** 1 week  
**Dependencies:** None  
**Key files:** `cmd/aegisclaw/cmd_doctor.go`, `internal/doctor/`

---

### 4.5 — Docker-Compose Skill Orchestration

**Goal:** Support multi-container skills with coordinated sandboxing.

**Steps:**

1. **Extend manifest format:**
   ```yaml
   name: web-agent
   version: 1.0.0
   platform: docker-compose
   compose_file: docker-compose.yml
   services:
     agent:
       scopes:
         - net.outbound:api.openai.com
         - net.internal:redis
     redis:
       scopes:
         - net.internal:agent
   ```

2. **Implement compose orchestration:**
   ```go
   func RunCompose(manifest *SkillManifest) error {
       // 1. Create isolated Docker network for the skill
       networkName := fmt.Sprintf("aegisclaw-%s-%s", manifest.Name, uuid.New().String()[:8])
       exec.Command("docker", "network", "create", "--internal", networkName).Run()
       
       // 2. Apply security constraints per service
       for _, service := range manifest.Services {
           applySeccompProfile(service)
           applyNetworkPolicy(service, networkName)
           applyScopeRestrictions(service)
       }
       
       // 3. Run docker-compose with constraints
       cmd := exec.Command("docker", "compose", "-f", manifest.ComposeFile, "up", "--abort-on-container-exit")
       cmd.Env = append(os.Environ(), fmt.Sprintf("AEGISCLAW_NETWORK=%s", networkName))
       
       // 4. Stream logs with secret redaction
       // 5. Cleanup network on exit
   }
   ```

3. **Network policy enforcement** — internal services can only talk to each other, external egress controlled by scopes

4. **Unified audit logging** — all containers in the compose stack log to a single audit stream

**Estimated effort:** 3–4 weeks  
**Dependencies:** Docker Compose, existing sandbox code  
**Key files:** `internal/sandbox/compose.go`, `internal/sandbox/network.go`

---

### 4.6 — Notification System

**Goal:** Alert users on pending approvals, denied actions, and emergencies.

**Steps:**

1. **Define notification events:**
   ```go
   type NotificationEvent string
   const (
       EventApprovalPending  NotificationEvent = "approval_pending"
       EventActionDenied     NotificationEvent = "action_denied"
       EventEmergencyLockdown NotificationEvent = "emergency_lockdown"
       EventSkillCompleted   NotificationEvent = "skill_completed"
       EventSecretLeakDetected NotificationEvent = "secret_leak"
   )
   ```

2. **Webhook transport:**
   ```go
   type WebhookNotifier struct {
       URL     string
       Secret  string // HMAC signing
   }
   
   func (w *WebhookNotifier) Send(event NotificationEvent, payload map[string]interface{}) error {
       body, _ := json.Marshal(payload)
       sig := hmac.New(sha256.New, []byte(w.Secret))
       sig.Write(body)
       
       req, _ := http.NewRequest("POST", w.URL, bytes.NewReader(body))
       req.Header.Set("X-AegisClaw-Signature", hex.EncodeToString(sig.Sum(nil)))
       return http.DefaultClient.Do(req)
   }
   ```

3. **Slack transport:**
   ```go
   type SlackNotifier struct {
       WebhookURL string
   }
   
   func (s *SlackNotifier) Send(event NotificationEvent, payload map[string]interface{}) error {
       msg := formatSlackMessage(event, payload) // Rich Block Kit message
       body, _ := json.Marshal(msg)
       _, err := http.Post(s.WebhookURL, "application/json", bytes.NewReader(body))
       return err
   }
   ```

4. **Email transport** — use SMTP or SendGrid/SES

5. **Configuration:**
   ```yaml
   # ~/.aegisclaw/config.yaml
   notifications:
     - type: slack
       webhook_url: "https://hooks.slack.com/services/..."
       events: [approval_pending, emergency_lockdown]
     - type: webhook
       url: "https://your-server.com/aegisclaw-events"
       secret: "hmac-secret"
       events: [action_denied, secret_leak]
   ```

**Estimated effort:** 2–3 weeks  
**Dependencies:** None (standard HTTP)  
**Key files:** `internal/notifications/`, `internal/notifications/slack.go`, `internal/notifications/webhook.go`

---

### 4.7 — Policy Templates & Shell Completions

**Goal:** Lower the barrier to writing good policies.

**Steps:**

1. **Policy templates** — ship 3 built-in Rego policies:
   ```rego
   # policies/strict.rego
   package aegisclaw.policy
   default allow = false
   # Everything requires approval
   allow { input.approval == true }
   
   # policies/standard.rego  
   package aegisclaw.policy
   default allow = false
   allow { input.scope_risk == "low" }
   allow { input.scope_risk == "medium"; input.skill_signed == true }
   allow { input.approval == true }
   
   # policies/permissive.rego
   package aegisclaw.policy
   default allow = true
   deny { input.scope_risk == "critical"; input.approval != true }
   ```

2. **Select during init:** `aegisclaw init` wizard offers policy template choice

3. **Shell completions** using `cobra`'s built-in completion generation:
   ```go
   rootCmd.GenBashCompletionFile("completions/aegisclaw.bash")
   rootCmd.GenZshCompletionFile("completions/aegisclaw.zsh")
   rootCmd.GenFishCompletionFile("completions/aegisclaw.fish")
   rootCmd.GenPowerShellCompletionFile("completions/aegisclaw.ps1")
   ```

4. **Distribute completions** in release archives and via install script

**Estimated effort:** 1 week  
**Dependencies:** `cobra` (already used)  
**Key files:** `configs/policies/`, `completions/`

---

## v0.5.x: Advanced Security

### 5.1 — Kata Containers / Firecracker Support

**Goal:** MicroVM-based isolation for maximum security.

**Steps:**

1. **Abstract the runtime interface:**
   ```go
   type SandboxRuntime interface {
       Run(ctx context.Context, config *RunConfig) (*RunResult, error)
       Kill(containerID string) error
       Inspect(containerID string) (*InspectResult, error)
   }
   
   // Implementations:
   type DockerRuntime struct { ... }
   type GVisorRuntime struct { ... }
   type KataRuntime struct { ... }    // NEW
   type FirecrackerRuntime struct { ... } // NEW
   ```

2. **Kata Containers implementation:**
   ```go
   type KataRuntime struct{}
   
   func (k *KataRuntime) Run(ctx context.Context, config *RunConfig) (*RunResult, error) {
       // Use Docker with Kata runtime
       args := []string{
           "run", "--runtime=kata-runtime",
           "--rm", "--read-only",
           "--security-opt", "no-new-privileges",
       }
       args = append(args, applyScopeConstraints(config.Scopes)...)
       args = append(args, config.Image)
       args = append(args, config.Command...)
       return execDocker(ctx, args)
   }
   ```

3. **Firecracker implementation:**
   - Use `firecracker-go-sdk` for MicroVM management
   - Create a rootfs from the skill's container image
   - Boot a MicroVM with constrained resources
   - More complex — requires kernel image and rootfs preparation

4. **Runtime selection:**
   ```yaml
   # ~/.aegisclaw/config.yaml
   sandbox:
     runtime: kata  # docker | gvisor | kata | firecracker
   ```

5. **Fallback chain:** Firecracker → Kata → gVisor → Docker

**Estimated effort:** 4–6 weeks  
**Dependencies:** Kata Containers or Firecracker installed on host  
**Key files:** `internal/sandbox/kata.go`, `internal/sandbox/firecracker.go`

---

### 5.2 — Pluggable Vault Backends

**Goal:** Support HashiCorp Vault, Infisical, Bitwarden, and AWS Secrets Manager.

**Steps:**

1. **Define secret store interface:**
   ```go
   type SecretStore interface {
       Get(key string) (string, error)
       Set(key string, value string) error
       Delete(key string) error
       List() ([]string, error)
   }
   
   // Implementations:
   type AgeStore struct { ... }      // existing
   type VaultStore struct { ... }    // NEW
   type InfisicalStore struct { ... } // NEW
   type AWSSecretsStore struct { ... } // NEW
   ```

2. **HashiCorp Vault implementation:**
   ```go
   type VaultStore struct {
       client *vault.Client
       mount  string
       path   string
   }
   
   func NewVaultStore(addr, token, mount, path string) (*VaultStore, error) {
       config := vault.DefaultConfig()
       config.Address = addr
       client, err := vault.NewClient(config)
       client.SetToken(token)
       return &VaultStore{client: client, mount: mount, path: path}, err
   }
   
   func (v *VaultStore) Get(key string) (string, error) {
       secret, err := v.client.KVv2(v.mount).Get(context.Background(), v.path+"/"+key)
       if err != nil { return "", err }
       return secret.Data["value"].(string), nil
   }
   ```

3. **Configuration:**
   ```yaml
   secrets:
     backend: vault  # age | vault | infisical | aws-secrets-manager
     vault:
       address: "https://vault.example.com"
       token_env: "VAULT_TOKEN"
       mount: "secret"
       path: "aegisclaw"
   ```

4. **Secret rotation support:**
   ```go
   type RotatableStore interface {
       SecretStore
       Rotate(key string) (newValue string, err error)
       SetRotationSchedule(key string, interval time.Duration) error
   }
   ```

5. **Ephemeral secrets** — inject short-lived credentials into sandbox environment that expire after execution:
   ```go
   func (s *SecretInjector) InjectEphemeral(containerID string, key string, ttl time.Duration) error {
       value, _ := s.store.Get(key)
       // Set env var in container
       // Schedule cleanup after TTL
       go func() {
           time.Sleep(ttl)
           s.revokeFromContainer(containerID, key)
       }()
       return nil
   }
   ```

**Estimated effort:** 4–5 weeks  
**Dependencies:** `hashicorp/vault/api`, `aws-sdk-go-v2`, HTTP clients for Infisical  
**Key files:** `internal/secrets/vault.go`, `internal/secrets/aws.go`, `internal/secrets/infisical.go`, `internal/secrets/interface.go`

---

### 5.3 — NeMo Guardrails Integration

**Goal:** LLM prompt protection layer for AI agent interactions.

**Steps:**

1. **Architecture decision** — NeMo Guardrails is Python-based, so integrate as a sidecar:
   ```
   Agent → AegisClaw Proxy → NeMo Guardrails (sidecar) → LLM API
   ```

2. **Deploy NeMo Guardrails sidecar:**
   ```dockerfile
   # internal/guardrails/Dockerfile
   FROM python:3.11-slim
   RUN pip install nemoguardrails
   COPY config/ /app/config/
   COPY server.py /app/
   EXPOSE 8090
   CMD ["python", "/app/server.py"]
   ```

3. **Guardrails config:**
   ```yaml
   # config/config.yml
   models:
     - type: main
       engine: openai
       model: gpt-4
   
   rails:
     input:
       flows:
         - self check input  # Block prompt injection
     output:
       flows:
         - self check output  # Block harmful output
   ```

4. **Proxy implementation in Go:**
   ```go
   type GuardrailsProxy struct {
       guardrailsURL string
       targetURL     string
   }
   
   func (g *GuardrailsProxy) Intercept(req *http.Request) (*http.Response, error) {
       // 1. Extract prompt from request body
       // 2. Send to NeMo Guardrails for input check
       // 3. If blocked → return denial response + log to audit
       // 4. If allowed → forward to LLM API
       // 5. Check response with NeMo output rails
       // 6. Return sanitised response
   }
   ```

5. **Enable via config:**
   ```yaml
   guardrails:
     enabled: true
     nemo_url: "http://localhost:8090"
     block_on_input_violation: true
     log_all_prompts: true
   ```

6. **Audit logging** — every intercepted prompt/response logged with guardrails decision

**Estimated effort:** 3–4 weeks  
**Dependencies:** Docker (for sidecar), NeMo Guardrails Python package  
**Key files:** `internal/guardrails/`, `internal/guardrails/proxy.go`, `internal/guardrails/Dockerfile`

---

### 5.4 — Runtime Behaviour Profiling

**Goal:** Learn normal behaviour per skill and flag anomalies.

**Steps:**

1. **Capture syscall and network profiles** during a "learning" phase:
   ```go
   type BehaviourProfile struct {
       SkillName      string
       SyscallCounts  map[string]int    // syscall → count
       NetworkTargets []string           // observed DNS/IP destinations
       FileAccess     []string           // observed file paths
       MaxMemoryMB    int
       MaxCPUPercent  float64
       SampleCount    int               // number of runs in learning phase
   }
   ```

2. **Learning mode:**
   ```bash
   aegisclaw sandbox run-registered web-search --learn --runs 10
   ```
   - Run the skill N times, record all syscalls (via `strace` or seccomp audit), network connections, and resource usage
   - Aggregate into a baseline profile

3. **Enforce mode:**
   - On subsequent runs, compare real-time behaviour against the profile
   - Flag anomalies: new syscalls, unexpected network targets, file access outside learned paths
   - Action: log warning, block execution, or trigger approval flow (configurable)

4. **Store profiles** in `~/.aegisclaw/profiles/{skill-name}.json`

**Estimated effort:** 4–5 weeks  
**Dependencies:** `strace` or seccomp audit log parsing  
**Key files:** `internal/profiling/`, `internal/profiling/learner.go`, `internal/profiling/enforcer.go`

---

### 5.5 — Auth & Access Control

**Goal:** Secure the dashboard and API for team deployments.

**Steps:**

1. **Tailscale/WireGuard integration:**
   - Add `--tailscale` flag to `aegisclaw serve`
   - Use `tsnet` library to bind the HTTP server to a Tailscale address
   ```go
   import "tailscale.com/tsnet"
   
   func serveTailscale(port int) error {
       s := &tsnet.Server{Hostname: "aegisclaw"}
       ln, err := s.Listen("tcp", fmt.Sprintf(":%d", port))
       return http.Serve(ln, handler)
   }
   ```

2. **Authelia/Keycloak SSO:**
   - Add OIDC middleware to the web server:
   ```go
   func OIDCMiddleware(next http.Handler) http.Handler {
       return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
           token := r.Header.Get("Authorization")
           claims, err := validateOIDCToken(token)
           if err != nil {
               http.Error(w, "Unauthorized", 401)
               return
           }
           ctx := context.WithValue(r.Context(), "user", claims)
           next.ServeHTTP(w, r.WithContext(ctx))
       })
   }
   ```

3. **RBAC roles:** `admin` (full access), `operator` (run skills, approve), `viewer` (read-only dashboard)

4. **mTLS for adapter communication:**
   - Generate client/server certificates during setup
   - Configure Go HTTP client/server with mutual TLS:
   ```go
   tlsConfig := &tls.Config{
       Certificates: []tls.Certificate{cert},
       ClientCAs:    caCertPool,
       ClientAuth:   tls.RequireAndVerifyClientCert,
   }
   ```

**Estimated effort:** 4–5 weeks  
**Dependencies:** `tsnet`, OIDC library, x509 certificate generation  
**Key files:** `internal/auth/`, `internal/auth/oidc.go`, `internal/auth/rbac.go`, `internal/auth/mtls.go`

---

## v0.6.x: Woo Factor & Ecosystem

### 6.1 — Live Threat Map Dashboard

**Goal:** Real-time animated mission control for agent activity.

**Steps:**

1. **WebSocket endpoint** for real-time events:
   ```go
   func handleWebSocket(w http.ResponseWriter, r *http.Request) {
       conn, _ := upgrader.Upgrade(w, r, nil)
       for event := range auditEventChannel {
           conn.WriteJSON(event)
       }
   }
   ```

2. **Frontend implementation** (extend existing dashboard):
   - Use D3.js or React Flow for animated visualisation
   - Skill executions → pulsing green nodes
   - Denied actions → red flash with shake animation
   - Pending approvals → amber glow
   - Network connections → animated lines between nodes
   - Emergency lockdown → full-screen red overlay

3. **Layout:** Central "agent" node with orbiting skill nodes, connected by lines showing data flow

4. **Sound effects** (optional, toggle): subtle audio cues for approvals/denials

**Estimated effort:** 3–4 weeks  
**Dependencies:** WebSocket, D3.js or React Flow  
**Key files:** `cmd/aegisclaw/web/ws.go`, `dashboard/src/components/ThreatMap.tsx`

---

### 6.2 — Agent X-Ray Mode

**Goal:** Deep inspection of running skills in real-time.

**Steps:**

1. **Container inspection API:**
   ```go
   type ContainerInspection struct {
       PID           int
       Syscalls      []SyscallEvent     // live stream
       OpenFiles     []string
       NetworkConns  []NetConnection
       MemoryUsageMB float64
       CPUPercent    float64
       ScopeUsage    map[string]bool   // which scopes are actively being used
       Uptime        time.Duration
   }
   
   func InspectContainer(containerID string) (*ContainerInspection, error) {
       // Use Docker API for stats
       // Use /proc/{pid} for open files
       // Use strace or eBPF for syscalls
       // Use ss/netstat for connections
   }
   ```

2. **Dashboard panel** — click any running skill to see:
   - Live syscall stream (scrolling terminal)
   - Resource gauges (CPU, memory, disk I/O)
   - Network connection table with scope mapping
   - Open file handles with read/write indicators
   - Scope consumption visualization (used vs allowed)

3. **WebSocket streaming** of inspection data at 1-second intervals

**Estimated effort:** 3–4 weeks  
**Dependencies:** Docker API, WebSocket  
**Key files:** `internal/inspect/`, `dashboard/src/components/XRay.tsx`

---

### 6.3 — Security Posture Score & Badge

**Goal:** Gamified scoring of AegisClaw configuration quality.

**Steps:**

1. **Scoring algorithm:**
   ```go
   func CalculatePostureScore(config *Config) PostureScore {
       score := 0
       max := 0
       
       // Sandboxing (30 points)
       max += 30
       if config.Runtime == "firecracker" { score += 30 }
       else if config.Runtime == "kata" { score += 25 }
       else if config.Runtime == "gvisor" { score += 20 }
       else if config.Runtime == "docker" { score += 15 }
       
       // Secrets (20 points)
       max += 20
       if config.Secrets.Backend == "vault" { score += 20 }
       else if config.Secrets.Backend == "age" { score += 15 }
       if config.Secrets.RotationEnabled { score += 5 }
       
       // Policy (20 points)
       max += 20
       if config.Policy.Mode == "strict" { score += 20 }
       else if config.Policy.Mode == "standard" { score += 15 }
       
       // Audit (15 points)
       if config.Audit.Enabled { score += 10 }
       if config.Audit.IntegrityVerified { score += 5 }
       
       // Skills (15 points)
       if allSkillsSigned(config) { score += 15 }
       
       return PostureScore{Score: score, Max: max, Grade: gradeFromPct(score*100/max)}
   }
   ```

2. **CLI output:** `aegisclaw posture`
3. **Badge endpoint:** `GET /api/v1/badge → shields.io redirect`
4. **Dashboard widget** with radar chart

**Estimated effort:** 1–2 weeks  
**Dependencies:** None  
**Key files:** `internal/posture/`, `cmd/aegisclaw/cmd_posture.go`

---

### 6.4 — MCP Server

**Goal:** Expose AegisClaw as an MCP tool for AI assistants.

**Steps:**

1. **Implement MCP server** using the Model Context Protocol spec:
   ```go
   // MCP tool definitions
   tools := []MCPTool{
       {
           Name: "aegisclaw_run_skill",
           Description: "Run a sandboxed skill with AegisClaw security envelope",
           InputSchema: RunSkillSchema,
           Handler: handleRunSkill,
       },
       {
           Name: "aegisclaw_audit_query",
           Description: "Query AegisClaw audit logs",
           InputSchema: AuditQuerySchema,
           Handler: handleAuditQuery,
       },
       {
           Name: "aegisclaw_posture",
           Description: "Get current security posture score",
           Handler: handlePosture,
       },
   }
   ```

2. **Transport:** stdio (for Claude Code, Cursor) and SSE (for web-based tools)

3. **CLI command:** `aegisclaw mcp-server` starts the MCP server

4. **MCP config example** for Claude Code:
   ```json
   {
     "mcpServers": {
       "aegisclaw": {
         "command": "aegisclaw",
         "args": ["mcp-server"]
       }
     }
   }
   ```

**Estimated effort:** 2–3 weeks  
**Dependencies:** MCP protocol library  
**Key files:** `internal/mcp/`, `cmd/aegisclaw/cmd_mcp.go`

---

### 6.5 — Skill Marketplace

**Goal:** Community registry with ratings and security badges.

**Steps:**

1. **Registry API:**
   ```
   GET  /api/v1/skills                    # List/search
   GET  /api/v1/skills/{name}             # Detail
   POST /api/v1/skills                    # Publish (authenticated)
   GET  /api/v1/skills/{name}/audit       # Security audit results
   POST /api/v1/skills/{name}/rate        # Rate (1-5 stars)
   ```

2. **Publish workflow:**
   - Developer runs `aegisclaw skill publish ./my-skill/`
   - CLI builds Docker image, signs manifest, uploads to registry
   - Registry runs automated security scan (Trivy, Checkov)
   - Skill appears with "unverified" badge until manually reviewed

3. **Install workflow:**
   ```bash
   aegisclaw skill install registry.aegisclaw.dev/web-search
   ```

4. **Dashboard skill store** — browse, filter by category/rating, one-click install

5. **Can start simple** — Git-based registry (GitHub repo as registry) before building a full API

**Estimated effort:** 6–8 weeks  
**Dependencies:** Container registry, API server  
**Key files:** `internal/registry/`, `cmd/aegisclaw/cmd_skill.go`

---

### 6.6 — VS Code Extension

**Goal:** Sidebar panel for AegisClaw management from the editor.

**Steps:**

1. **Create VS Code extension** (`vscode-extension/`):
   - Language: TypeScript
   - Framework: VS Code Extension API

2. **Features:**
   - **Sidebar panel:** AegisClaw status, active skills, recent audit events
   - **Approval notifications:** VS Code notification popup for pending approvals with Approve/Deny buttons
   - **Audit stream:** Output channel showing live audit log
   - **Rego linting:** Inline diagnostics for policy files using OPA check
   - **Skill manifest validation:** Schema validation for `manifest.yaml` files

3. **Communication:** Connect to AegisClaw API via HTTP (localhost)

4. **Publish** to VS Code Marketplace

**Estimated effort:** 3–4 weeks  
**Dependencies:** AegisClaw API server running  
**Key files:** `vscode-extension/`

---

### 6.7 — `aegisclaw simulate`

**Goal:** Dry-run mode predicting skill behaviour without execution.

**Steps:**

1. **Parse skill manifest and image:**
   - Extract entrypoint, environment variables, network requirements from Dockerfile/manifest
   - Analyse command to predict file access patterns

2. **Static analysis of skill code** (if available):
   - Scan for file I/O operations, network calls, subprocess spawns
   - Map to expected scope requirements

3. **Output simulation report:**
   ```
   $ aegisclaw simulate web-search
   
   🔮 Simulation Report: web-search
   
   Predicted behaviour:
     📁 File access: /tmp/input (read), /tmp/output (write)
     🌐 Network: api.duckduckgo.com:443 (HTTPS)
     ⚡ Syscalls: read, write, socket, connect, close
     💾 Memory: ~50 MB estimated
     ⏱️  Duration: ~5s estimated
   
   Required scopes:
     ✅ net.outbound:api.duckduckgo.com (declared)
     ✅ files.read:/tmp/input (declared)
     ✅ files.write:/tmp/output (declared)
   
   Risk assessment: LOW
   ```

4. **Compare simulation with manifest** — flag undeclared required scopes

**Estimated effort:** 3–4 weeks  
**Dependencies:** Container image inspection, static analysis  
**Key files:** `internal/simulate/`, `cmd/aegisclaw/cmd_simulate.go`

---

## Long-Term Vision

### eBPF-Based Runtime Monitoring
- Use `cilium/ebpf` Go library for kernel-level observability
- Attach eBPF probes to trace syscalls, network flows, and file access
- Near-zero overhead compared to strace/seccomp audit
- **Effort:** 6–8 weeks

### Multi-Node Orchestration
- gRPC-based coordination between AegisClaw instances
- Centralised policy management server
- Unified audit log aggregation
- **Effort:** 8–12 weeks (significant architecture)

### AegisClaw Cloud
- Multi-tenant SaaS with org/team hierarchy
- Managed skill registry
- Hosted dashboards with SSO
- **Effort:** 3–6 months (separate project)

---

## Infrastructure & DevOps Requirements

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Build/Release | GoReleaser, GitHub Actions | Cross-platform binary builds |
| Container registry | ghcr.io | Skill images and sidecar containers |
| Package manager | Homebrew tap | macOS/Linux distribution |
| Dashboard | React/TypeScript | Web-based monitoring UI |
| MCP server | Go, stdio/SSE transport | AI assistant integration |
| Vault integration | HashiCorp Vault API | Enterprise secret management |
| eBPF | `cilium/ebpf` | Kernel-level monitoring (long-term) |

---

## Dependency Map

```
v0.4.1 (Distribution) ──→ v0.4.2 (Init wizard installs binaries)
v0.4.2 (Init wizard) ──→ v0.4.3 (Starter packs bundled in init)
                      ──→ v0.4.7 (Policy templates selected in init)

v0.5.1 (Kata/Firecracker) ──→ v0.6.3 (Posture score rewards stronger runtimes)
v0.5.2 (Vault backends) ──→ v0.5.2 (Ephemeral secrets in sandbox)
v0.5.4 (Behaviour profiling) ──→ v0.6.7 (Simulate uses learned profiles)

v0.4.5 (Compose orchestration) ──→ v0.6.5 (Marketplace supports compose skills)

v0.6.1 (Threat map) ──→ v0.6.2 (X-Ray mode embedded in threat map)
v0.6.4 (MCP server) — independent, can be built anytime
v0.6.6 (VS Code extension) — independent, needs API server
```
