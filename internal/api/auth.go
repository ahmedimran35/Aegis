package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/user/waf/internal/auth"
	wafmw "github.com/user/waf/internal/middleware"
	"golang.org/x/crypto/bcrypt"
)

const (
	maxAccountFailures  = 10
	accountLockDuration = 15 * time.Minute
)

// AuthHandler handles authentication endpoints.
type AuthHandler struct {
	service *auth.Service
	rdb     *redis.Client
}

// Pool returns the underlying Postgres pool for handlers that need to
// look up user metadata not carried in the JWT claims.
func (h *AuthHandler) Pool() *pgxpool.Pool {
	if h.service == nil {
		return nil
	}
	return h.service.Pool()
}

// NewAuthHandler creates a new auth handler.
func NewAuthHandler(service *auth.Service, rdb *redis.Client) *AuthHandler {
	return &AuthHandler{service: service, rdb: rdb}
}

// validatePassword delegates to the canonical auth.ValidatePassword
// policy (H-16). Keeps the api surface stable while removing the duplicate.
func validatePassword(pw string) error {
	return auth.ValidatePassword(pw)
}

// hashPassword hashes a password with bcrypt.
func hashPassword(pw string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), 12)
	return string(hash), err
}

// Login authenticates a user and returns a JWT token.
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}

	if req.Username == "" || req.Password == "" {
		RespondError(w, http.StatusBadRequest, "MISSING_FIELDS", "username and password required")
		return
	}

	ctx := r.Context()

	// Account-level lockout check (fail-closed on Redis errors)
	if locked, err := h.isAccountLocked(ctx, req.Username); err != nil {
		log.Printf("auth: lockout check failed for %s: %v — blocking as precaution", req.Username, err)
		RespondError(w, http.StatusServiceUnavailable, "AUTH_ERROR", "authentication service temporarily unavailable")
		return
	} else if locked {
		RespondError(w, http.StatusTooManyRequests, "ACCOUNT_LOCKED", "account temporarily locked due to too many failed attempts")
		return
	}

	user, token, err := h.service.Authenticate(ctx, req.Username, req.Password)
	if err != nil {
		h.recordLoginFailure(ctx, req.Username)
		RespondError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "invalid username or password")
		return
	}

	// Successful login — clear failure counter
	h.clearLoginFailures(ctx, req.Username)

	// CRITICAL: if TOTP is enabled, issue only a restricted pre-MFA
	// token. AuthMiddleware permits this token solely on /auth/totp/verify
	// and /auth/me until successful verification issues a fresh token with
	// must_mfa=false.
	if hasMFA, mfaErr := h.service.HasTOTPEnabled(ctx, user.ID); mfaErr == nil && hasMFA {
		user.MustMFA = true
	}

	// Generate session fingerprint from login request for token binding
	fp := generateLoginFingerprint(r)

	// Generate token with fingerprint binding
	var newToken string
	newToken, err = h.service.GenerateTokenWithFingerprint(user, fp)
	token = newToken
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "TOKEN_ERROR", "failed to generate token")
		return
	}

	// Set token as HttpOnly cookie for XSS protection.
	// P-FIX (CWE-614): only honor X-Forwarded-Proto from a trusted proxy.
	// Otherwise an attacker can spoof the header to mark the cookie Secure
	// while the connection is still plaintext.
	secure := r.TLS != nil || (r.Header.Get("X-Forwarded-Proto") == "https" && wafmw.IsTrustedProxyReq(r))
	// P-FIX: on TLS, use the __Host- cookie name prefix which forbids the
	// Domain attribute and forces Secure + Path=/, preventing subdomain
	// cookie injection and related attacks. Over plain HTTP (dev only),
	// fall back to the plain name because __Host- requires Secure.
	// H-18: scope the cookie to /api so static asset requests never carry
	// the JWT.
	http.SetCookie(w, &http.Cookie{
		Name:     AuthCookieName(secure),
		Value:    token,
		Path:     "/api",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400,
	})

	// P-FIX: also issue the CSRF cookie at login so the dashboard has a
	// valid token to echo back in X-CSRF-Token on subsequent mutations.
	if csrfTok, err := generateCSRFToken(); err == nil {
		http.SetCookie(w, &http.Cookie{
			Name:     csrfCookieName(secure),
			Value:    csrfTok,
			Path:     "/",
			Secure:   secure,
			HttpOnly: false, // JS must read this for double-submit
			SameSite: http.SameSiteStrictMode,
			MaxAge:   86400,
		})
	}

	resp := map[string]interface{}{
		"user":       user,
		"expires_in": 86400,
	}
	if user.MustChangePassword {
		resp["must_change_password"] = true
	}
	RespondJSON(w, http.StatusOK, resp)
}

func generateLoginFingerprint(r *http.Request) string {
	ua := r.UserAgent()
	accept := r.Header.Get("Accept-Language")
	enc := r.Header.Get("Accept-Encoding")
	acceptCharset := r.Header.Get("Accept-Charset")
	cacheControl := r.Header.Get("Cache-Control")
	conn := r.Header.Get("Connection")
	h := sha256.Sum256([]byte(ua + "|" + accept + "|" + enc + "|" + acceptCharset + "|" + cacheControl + "|" + conn))
	return hex.EncodeToString(h[:16])
}

// Logout revokes the current user's token by incrementing token_version.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		RespondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
		return
	}

	err := h.service.InvalidateUserTokens(r.Context(), claims.UserID)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "LOGOUT_FAILED", "failed to revoke tokens")
		return
	}

	// Clear the auth cookie (must match login cookie attributes for proper clearing).
	secure := r.TLS != nil || (r.Header.Get("X-Forwarded-Proto") == "https" && wafmw.IsTrustedProxyReq(r))
	authCookieName := AuthCookieName(secure)
	http.SetCookie(w, &http.Cookie{
		Name:     authCookieName,
		Value:    "",
		Path:     "/api",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
	// Also clear the CSRF cookie and the legacy plain-name variants so a
	// previously-issued cookie from a different transport mode is also
	// invalidated client-side.
	csrfName := csrfCookieName(secure)
	http.SetCookie(w, &http.Cookie{
		Name:     csrfName,
		Value:    "",
		Path:     "/",
		Secure:   secure,
		HttpOnly: false,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
	// Clear legacy plain-name cookies in case the operator previously
	// ran the server on HTTP and the client still has them.
	if secure {
		http.SetCookie(w, &http.Cookie{Name: "aegis_token", Value: "", Path: "/api", MaxAge: -1})
		http.SetCookie(w, &http.Cookie{Name: "aegis_csrf", Value: "", Path: "/", MaxAge: -1})
	}

	RespondJSON(w, http.StatusOK, map[string]string{"message": "logged out successfully"})
}

// ChangePassword changes the authenticated user's password.
func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		RespondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
		return
	}

	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}

	if err := validatePassword(req.NewPassword); err != nil {
		RespondError(w, http.StatusBadRequest, "WEAK_PASSWORD", err.Error())
		return
	}

	if err := h.service.ChangePassword(r.Context(), claims.UserID, req.OldPassword, req.NewPassword); err != nil {
		RespondError(w, http.StatusBadRequest, "CHANGE_FAILED", "password change failed: invalid old password or server error")
		return
	}

	RespondJSON(w, http.StatusOK, map[string]string{"message": "password changed successfully"})
}

func (h *AuthHandler) loginFailKey(username string) string {
	return "login:fail:" + username
}

func (h *AuthHandler) isAccountLocked(ctx context.Context, username string) (bool, error) {
	if h.rdb == nil {
		return false, nil
	}
	key := h.loginFailKey(username)
	count, err := h.rdb.Get(ctx, key).Int()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return count >= maxAccountFailures, nil
}

func (h *AuthHandler) recordLoginFailure(ctx context.Context, username string) {
	if h.rdb == nil {
		return
	}
	key := h.loginFailKey(username)
	pipe := h.rdb.Pipeline()
	pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, accountLockDuration)
	pipe.Exec(ctx)
}

func (h *AuthHandler) clearLoginFailures(ctx context.Context, username string) {
	if h.rdb == nil {
		return
	}
	h.rdb.Del(ctx, h.loginFailKey(username))
}
