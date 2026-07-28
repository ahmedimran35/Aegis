package middleware

import (
	"net/http"

	"github.com/user/waf/internal/auth"
)

// Role hierarchy: admin > editor > analyst > viewer
var roleHierarchy = map[string]int{
	"viewer":  1,
	"analyst": 2,
	"editor":  3,
	"admin":   4,
}

// RequireRole creates middleware that requires a minimum role level.
func RequireRole(minRole string) func(http.Handler) http.Handler {
	minLevel := roleHierarchy[minRole]

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := auth.ClaimsFromContext(r.Context())
			if claims == nil {
				writeAuthError(w, http.StatusUnauthorized, "authentication required")
				return
			}

			userLevel := roleHierarchy[claims.Role]
			if userLevel < minLevel {
				writeError(w, http.StatusForbidden, "INSUFFICIENT_ROLE",
					"requires "+minRole+" or higher")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
