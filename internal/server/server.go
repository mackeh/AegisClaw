package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/mackeh/AegisClaw/internal/agent"
	"github.com/mackeh/AegisClaw/internal/audit"
	"github.com/mackeh/AegisClaw/internal/config"
	"github.com/mackeh/AegisClaw/internal/sandbox"
	"github.com/mackeh/AegisClaw/internal/server/ui"
	"github.com/mackeh/AegisClaw/internal/skill"
	"github.com/mackeh/AegisClaw/internal/system"
	"github.com/mackeh/AegisClaw/internal/xray"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Request represents a skill execution request
type Request struct {
	Skill   string   `json:"skill"`
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

// InstallRequest represents a request to install a skill
type InstallRequest struct {
	Name string `json:"name"`
}

// Response represents the result of a skill execution
type Response struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	Error    string `json:"error,omitempty"`
}

// Server handles tool execution requests
type Server struct {
	Port int
	Hub  *Hub
}

func NewServer(port int) *Server {
	return &Server{Port: port, Hub: NewHub()}
}

func (s *Server) Start() error {
	// UI
	http.HandleFunc("/", s.handleIndex)

	// API
	http.HandleFunc("/api/skills", s.handleListSkills)
	http.HandleFunc("/api/logs", s.handleListLogs)
	http.HandleFunc("/api/metrics", promhttp.Handler().ServeHTTP)
	http.HandleFunc("/api/logs/verify", s.handleVerifyLogs)
	http.HandleFunc("/api/system/lockdown", s.handleSystemLockdown)
	http.HandleFunc("/api/system/unlock", s.handleSystemUnlock)
	http.HandleFunc("/api/system/status", s.handleSystemStatus)
	http.HandleFunc("/api/registry/search", s.handleRegistrySearch)
	http.HandleFunc("/api/registry/install", s.handleRegistryInstall)
	http.HandleFunc("/api/execute/stream", s.handleExecuteStream)
	http.HandleFunc("/api/ws", s.Hub.ServeWS)
	http.HandleFunc("/api/xray", s.handleXray)
	http.HandleFunc("/execute", s.handleExecute)
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	fmt.Printf("📡 AegisClaw API listening on 127.0.0.1:%d...\n", s.Port)
	fmt.Printf("📊 Dashboard available at http://127.0.0.1:%d\n", s.Port)
	return http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", s.Port), nil)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	content, err := ui.Content.ReadFile("index.html")
	if err != nil {
		http.Error(w, "Dashboard not found", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	w.Write(content)
}

func (s *Server) handleListSkills(w http.ResponseWriter, r *http.Request) {
	cfgDir, _ := config.DefaultConfigDir()
	skillsDir := filepath.Join(cfgDir, "skills")
	manifests, _ := skill.ListSkills(skillsDir)
	localManifests, _ := skill.ListSkills("skills")
	manifests = append(manifests, localManifests...)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(manifests)
}

func (s *Server) handleListLogs(w http.ResponseWriter, r *http.Request) {
	cfgDir, _ := config.DefaultConfigDir()
	logPath := filepath.Join(cfgDir, "audit", "audit.log")
	entries, _ := audit.ReadAll(logPath) // Ignore error, return empty list if failed

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}


func (s *Server) handleXray(w http.ResponseWriter, r *http.Request) {
	inspector, err := xray.NewInspector()
	if err != nil {
		http.Error(w, fmt.Sprintf("xray: %v", err), http.StatusInternalServerError)
		return
	}

	snapshots, err := inspector.ListAegisClaw(r.Context())
	if err != nil {
		http.Error(w, fmt.Sprintf("xray list: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"containers": snapshots,
		"count":      len(snapshots),
	})
}

func (s *Server) handleSystemStatus(w http.ResponseWriter, r *http.Request) {
	status := "active"
	if system.IsLockedDown() {
		status = "lockdown"
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": status})
}

func (s *Server) handleSystemLockdown(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	fmt.Println("🚨 EMERGENCY LOCKDOWN TRIGGERED!")
	system.Lockdown()

	// Kill all containers
	exec, err := sandbox.NewDockerExecutor()
	if err == nil {
		go exec.KillAll(r.Context()) // Run in background to not block response
	}

	s.Hub.Broadcast(WSEvent{Type: EventLockdown, Data: map[string]string{"status": "lockdown"}})

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"lockdown"}`))
}

func (s *Server) handleSystemUnlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	system.Unlock()
	fmt.Println("✅ System Unlocked.")

	s.Hub.Broadcast(WSEvent{Type: EventStatus, Data: map[string]string{"status": "active"}})

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"active"}`))
}

func (s *Server) handleVerifyLogs(w http.ResponseWriter, r *http.Request) {
	cfgDir, _ := config.DefaultConfigDir()
	logPath := filepath.Join(cfgDir, "audit", "audit.log")
	
	valid, err := audit.Verify(logPath)
	
	status := "valid"
	message := "Audit log integrity verified (hash chain is unbroken)."
	if err != nil {
		status = "error"
		message = err.Error()
	} else if !valid {
		status = "invalid"
		message = "Audit log integrity check failed."
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  status,
		"message": message,
	})
}

func (s *Server) handleRegistrySearch(w http.ResponseWriter, r *http.Request) {
	cfg, err := config.LoadDefault()
	if err != nil {
		http.Error(w, "Failed to load config", http.StatusInternalServerError)
		return
	}

	if cfg.Registry.URL == "" {
		http.Error(w, "Registry URL not configured", http.StatusBadRequest)
		return
	}

	index, err := skill.SearchRegistry(cfg.Registry.URL)
	if err != nil {
		http.Error(w, fmt.Sprintf("Registry error: %v", err), http.StatusBadGateway)
		return
	}

	query := strings.ToLower(r.URL.Query().Get("q"))
	var results []skill.RegistrySkill

	if query == "" {
		results = index.Skills
	} else {
		for _, s := range index.Skills {
			if strings.Contains(strings.ToLower(s.Name), query) || strings.Contains(strings.ToLower(s.Description), query) {
				results = append(results, s)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func (s *Server) handleRegistryInstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req InstallRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	cfg, err := config.LoadDefault()
	if err != nil {
		http.Error(w, "Failed to load config", http.StatusInternalServerError)
		return
	}

	if cfg.Registry.URL == "" {
		http.Error(w, "Registry URL not configured", http.StatusBadRequest)
		return
	}

	cfgDir, _ := config.DefaultConfigDir()
	skillsDir := filepath.Join(cfgDir, "skills")

	if err := skill.InstallSkill(req.Name, skillsDir, cfg.Registry.URL, cfg.Registry.TrustKeys); err != nil {
		http.Error(w, fmt.Sprintf("Install failed: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

func (s *Server) handleExecuteStream(w http.ResponseWriter, r *http.Request) {
	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Flush headers immediately
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}
	flusher.Flush()

	skillName := r.URL.Query().Get("skill")
	cmdName := r.URL.Query().Get("command")
	// For simplicity, args are not parsed from query yet, assuming no args or simple string split if needed
	// Better way: accept POST with JSON body for args, but EventSource implies GET.
	// We'll stick to basic no-args for "Whoo" demo or simple query param
	
	if skillName == "" || cmdName == "" {
		fmt.Fprintf(w, "event: error\ndata: Missing skill or command\n\n")
		return
	}

	// 1. Find manifest
	cfgDir, _ := config.DefaultConfigDir()
	searchDirs := []string{filepath.Join(cfgDir, "skills"), "skills"}
	var m *skill.Manifest
	for _, dir := range searchDirs {
		manifestPath := filepath.Join(dir, skillName, "skill.yaml")
		found, err := skill.LoadManifest(manifestPath)
		if err == nil {
			m = found
			break
		}
	}

	if m == nil {
		fmt.Fprintf(w, "event: error\ndata: Skill not found\n\n")
		return
	}

	// 2. Prepare Writers
	sseWriter := &SSEWriter{w: w, f: flusher}

	// 3. Execute
	_, err := agent.ExecuteSkillWithStream(r.Context(), m, cmdName, []string{}, sseWriter, sseWriter)
	
	if err != nil {
		fmt.Fprintf(w, "event: error\ndata: %s\n\n", err.Error())
	} else {
		fmt.Fprintf(w, "event: done\ndata: Execution complete\n\n")
	}
	flusher.Flush()
}

type SSEWriter struct {
	w http.ResponseWriter
	f http.Flusher
}

func (s *SSEWriter) Write(p []byte) (n int, err error) {
	// SSE format: data: <content>\n\n
	// We need to be careful with newlines. 
	// Simple approach: write line by line or raw chunk.
	// Raw chunk is better for terminal stream, client handles buffering.
	// We'll treat the payload as raw data.
	
	// Escape newlines for SSE data field if necessary, or just send raw lines.
	// Actually, for a terminal stream, it's easier to send JSON chunks or just raw lines prefixed with data:
	
	// Let's send it as a JSON object to handle special chars safely
	payload, _ := json.Marshal(string(p))
	fmt.Fprintf(s.w, "data: %s\n\n", payload)
	s.f.Flush()
	return len(p), nil
}

func (s *Server) handleExecute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 1. Find the skill manifest
	cfgDir, _ := config.DefaultConfigDir()
	
	// Check standard locations
	searchDirs := []string{
		filepath.Join(cfgDir, "skills"),
		"skills",
	}

	var m *skill.Manifest
	for _, dir := range searchDirs {
		manifestPath := filepath.Join(dir, req.Skill, "skill.yaml")
		found, err := skill.LoadManifest(manifestPath)
		if err == nil {
			m = found
			break
		}
	}

	if m == nil {
		s.sendResponse(w, http.StatusNotFound, Response{Error: fmt.Sprintf("skill '%s' not found", req.Skill)})
		return
	}

	// 2. Execute
	result, err := agent.ExecuteSkill(r.Context(), m, req.Command, req.Args)
	if err != nil {
		s.sendResponse(w, http.StatusInternalServerError, Response{Error: err.Error()})
		return
	}

	// 3. Return result
	s.sendResponse(w, http.StatusOK, Response{
		ExitCode: result.ExitCode,
		Stdout:   result.Stdout,
		Stderr:   result.Stderr,
	})
}

func (s *Server) sendResponse(w http.ResponseWriter, status int, resp Response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(resp)
}
