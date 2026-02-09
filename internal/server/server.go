package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"

	"github.com/mackeh/AegisClaw/internal/agent"
	"github.com/mackeh/AegisClaw/internal/config"
	"github.com/mackeh/AegisClaw/internal/skill"
)

// Request represents a skill execution request
type Request struct {
	Skill   string   `json:"skill"`
	Command string   `json:"command"`
	Args    []string `json:"args"`
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
}

func NewServer(port int) *Server {
	return &Server{Port: port}
}

func (s *Server) Start() error {
	http.HandleFunc("/execute", s.handleExecute)
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	fmt.Printf("📡 AegisClaw API listening on 127.0.0.1:%d...\n", s.Port)
	return http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", s.Port), nil)
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
