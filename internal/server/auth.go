package server

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// Role represents an RBAC role for API access.
type Role string

const (
	RoleAdmin    Role = "admin"    // full access
	RoleOperator Role = "operator" // run skills, approve, view
	RoleViewer   Role = "viewer"   // read-only dashboard and logs
)

// AuthConfig holds API key authentication configuration.
type AuthConfig struct {
	Enabled bool      `yaml:"enabled"`
	Keys    []APIKey  `yaml:"keys"`
}

// APIKey maps a token to a role.
type APIKey struct {
	Name  string `yaml:"name"`
	Token string `yaml:"token"`
	Role  Role   `yaml:"role"`
}

// AuthMiddleware enforces API key authentication and RBAC.
// If auth is not enabled, all requests pass through.
func AuthMiddleware(cfg AuthConfig, requiredRole Role, next http.HandlerFunc) http.HandlerFunc {
	if !cfg.Enabled {
		return next
	}

	return func(w http.ResponseWriter, r *http.Request) {
		token := extractToken(r)
		if token == "" {
			http.Error(w, `{"error":"authentication required"}`, http.StatusUnauthorized)
			return
		}

		role, ok := authenticateToken(cfg.Keys, token)
		if !ok {
			http.Error(w, `{"error":"invalid API key"}`, http.StatusUnauthorized)
			return
		}

		if !hasPermission(role, requiredRole) {
			http.Error(w, `{"error":"insufficient permissions"}`, http.StatusForbidden)
			return
		}

		next(w, r)
	}
}

func extractToken(r *http.Request) string {
	// Check Authorization header: "Bearer <token>"
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}

	// Check X-API-Key header
	if key := r.Header.Get("X-API-Key"); key != "" {
		return key
	}

	// Check query parameter (for SSE/WebSocket connections)
	if key := r.URL.Query().Get("api_key"); key != "" {
		return key
	}

	return ""
}

func authenticateToken(keys []APIKey, token string) (Role, bool) {
	for _, k := range keys {
		if subtle.ConstantTimeCompare([]byte(k.Token), []byte(token)) == 1 {
			return k.Role, true
		}
	}
	return "", false
}

// hasPermission checks if the given role meets the required role level.
// admin > operator > viewer
func hasPermission(have, need Role) bool {
	levels := map[Role]int{
		RoleAdmin:    3,
		RoleOperator: 2,
		RoleViewer:   1,
	}
	return levels[have] >= levels[need]
}
