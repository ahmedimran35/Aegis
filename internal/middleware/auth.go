package middleware

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/user/waf/internal/auth"
)

// AuthMiddleware validates JWT tokens on protected routes.
func AuthMiddleware(service *auth.Service, sessionTracker *SessionTracker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var tokenStr string

			// Try Authorization header first
			authHeader := r.Header.Get("Authorization")
			if authHeader != "" {
				parts := strings.SplitN(authHeader, " ", 2)
				if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
					tokenStr = parts[1]
				}
			}

			// Fallback to HttpOnly cookie. Support both the legacy
			// `aegis_token` name and the new __Host- prefixed name
			// issued when the connection is over TLS.
			if tokenStr == "" {
				for _, name := range []string{"__Host-aegis_token", "aegis_token"} {
					if cookie, err := r.Cookie(name); err == nil {
						tokenStr = cookie.Value
						break
					}
				}
			}

			if tokenStr == "" {
				writeAuthError(w, http.StatusUnauthorized, "authorization required")
				return
			}

			// ValidateToken now performs signature + expiry + token_version
			// (DB-side revocation) in a single call. Auth callers no longer
			// need to fetch the DB version themselves.
			claims, err := service.ValidateToken(r.Context(), tokenStr)
			if err != nil {
				writeAuthError(w, http.StatusUnauthorized, "invalid or expired token")
				return
			}

			// Validate session fingerprint binding (if present in token)
			if claims.SessionFingerprint != "" && sessionTracker != nil {
				sessionID := SessionIDFromContext(r.Context())
				if sessionID != "" {
					storedFP, err := sessionTracker.GetFingerprint(r.Context(), sessionID)
					if err != nil {
						log.Printf("auth: fingerprint lookup failed: %v", err)
					} else if storedFP != "" && storedFP != claims.SessionFingerprint {
						log.Printf("auth: fingerprint mismatch for user %s (session: %s)", claims.Username, sessionID)
						writeAuthError(w, http.StatusUnauthorized, "session fingerprint mismatch — possible session hijack")
						return
					}
				}
			}

			// Enforce must_change_password — allow change-password and logout
			if claims.MustChangePassword && r.URL.Path != "/api/v1/auth/change-password" && r.URL.Path != "/api/v1/auth/logout" {
				writeError(w, http.StatusForbidden, "PASSWORD_CHANGE_REQUIRED", "you must change your password before accessing this resource")
				return
			}

			// Enforce must_mfa — pre-MFA tokens can only hit /auth/totp/verify
			// (which upgrades them) and /auth/me (so the UI can show "verify
			// your 2FA" state). All other endpoints require a fully-authenticated
			// token (must_mfa=false).
			if claims.MustMFA && r.URL.Path != "/api/v1/auth/totp/verify" && r.URL.Path != "/api/v1/auth/me" && r.URL.Path != "/api/v1/auth/logout" {
				writeError(w, http.StatusForbidden, "MFA_REQUIRED", "second-factor authentication required; call POST /auth/totp/verify")
				return
			}

			ctx := auth.ContextWithClaims(r.Context(), claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func writeAuthError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error": map[string]string{
			"code":    "UNAUTHORIZED",
			"message": message,
		},
	})
}
