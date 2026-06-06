package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleHarness(t *testing.T) {
	s := &Server{}

	req := httptest.NewRequest(http.MethodGet, "/api/harness", nil)
	rec := httptest.NewRecorder()
	s.handleHarness(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp struct {
		Planes []struct {
			Plane string `json:"plane"`
		} `json:"planes"`
		Adapters []struct {
			Name            string `json:"name"`
			RequiresSandbox bool   `json:"requires_sandbox"`
		} `json:"adapters"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(resp.Planes) != 4 {
		t.Fatalf("expected 4 planes, got %d", len(resp.Planes))
	}

	// The built-in adapters must be reported, and Hermes must require the sandbox.
	names := map[string]bool{}
	var hermesSandbox bool
	for _, a := range resp.Adapters {
		names[a.Name] = true
		if a.Name == "hermes" {
			hermesSandbox = a.RequiresSandbox
		}
	}
	for _, want := range []string{"generic", "openclaw", "hermes"} {
		if !names[want] {
			t.Errorf("missing adapter %q in %v", want, names)
		}
	}
	if !hermesSandbox {
		t.Error("hermes adapter should report requires_sandbox=true")
	}
}

func TestHandleHarnessRejectsPost(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodPost, "/api/harness", nil)
	rec := httptest.NewRecorder()
	s.handleHarness(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}
