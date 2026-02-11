package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthMiddleware_Disabled(t *testing.T) {
	called := false
	handler := AuthMiddleware(AuthConfig{Enabled: false}, RoleAdmin, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("handler should be called when auth is disabled")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestAuthMiddleware_MissingToken(t *testing.T) {
	handler := AuthMiddleware(AuthConfig{
		Enabled: true,
		Keys:    []APIKey{{Name: "test", Token: "secret", Role: RoleAdmin}},
	}, RoleViewer, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestAuthMiddleware_InvalidToken(t *testing.T) {
	handler := AuthMiddleware(AuthConfig{
		Enabled: true,
		Keys:    []APIKey{{Name: "test", Token: "secret", Role: RoleAdmin}},
	}, RoleViewer, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestAuthMiddleware_ValidToken_BearerHeader(t *testing.T) {
	called := false
	handler := AuthMiddleware(AuthConfig{
		Enabled: true,
		Keys:    []APIKey{{Name: "test", Token: "secret123", Role: RoleAdmin}},
	}, RoleViewer, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer secret123")
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("handler should be called with valid token")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestAuthMiddleware_ValidToken_APIKeyHeader(t *testing.T) {
	called := false
	handler := AuthMiddleware(AuthConfig{
		Enabled: true,
		Keys:    []APIKey{{Name: "test", Token: "mykey", Role: RoleOperator}},
	}, RoleViewer, func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-API-Key", "mykey")
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("handler should be called with X-API-Key header")
	}
}

func TestAuthMiddleware_InsufficientPermissions(t *testing.T) {
	handler := AuthMiddleware(AuthConfig{
		Enabled: true,
		Keys:    []APIKey{{Name: "viewer", Token: "viewerkey", Role: RoleViewer}},
	}, RoleAdmin, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("POST", "/api/system/lockdown", nil)
	req.Header.Set("Authorization", "Bearer viewerkey")
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestHasPermission(t *testing.T) {
	tests := []struct {
		have Role
		need Role
		want bool
	}{
		{RoleAdmin, RoleAdmin, true},
		{RoleAdmin, RoleOperator, true},
		{RoleAdmin, RoleViewer, true},
		{RoleOperator, RoleOperator, true},
		{RoleOperator, RoleViewer, true},
		{RoleOperator, RoleAdmin, false},
		{RoleViewer, RoleViewer, true},
		{RoleViewer, RoleOperator, false},
		{RoleViewer, RoleAdmin, false},
	}

	for _, tt := range tests {
		got := hasPermission(tt.have, tt.need)
		if got != tt.want {
			t.Errorf("hasPermission(%s, %s) = %v, want %v", tt.have, tt.need, got, tt.want)
		}
	}
}
