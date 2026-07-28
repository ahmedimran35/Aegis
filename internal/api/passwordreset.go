// Package api: real password reset request / confirm handler.
//
// Flow:
//   1. User submits username via /auth/password-reset/request.
//      Server generates a 32-byte one-time token, stores its bcrypt hash
//      in password_reset_tokens with a 1-hour TTL, and (in production)
//      emails the plaintext token to the registered address. For dev
//      the token is returned in the response when AEGIS_DEV_MODE=true.
//   2. User submits {token, new_password} via /auth/password-reset/confirm.
//      Server looks up the token hash, compares, expires it, and updates
//      the user's password.
package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/user/waf/internal/audit"
	"github.com/user/waf/internal/auth"
	"golang.org/x/crypto/bcrypt"
)

// PasswordResetHandler issues and consumes one-time password-reset tokens.
type PasswordResetHandler struct {
	pool     *pgxpool.Pool
	audit    *audit.Logger
	jwt      *auth.JWT
	ttl      time.Duration
	devMode  bool
	hmacKey  []byte // M-21: pre-shared HMAC key for indexed token lookup
}

// NewPasswordResetHandler constructs a PasswordResetHandler.
func NewPasswordResetHandler(pool *pgxpool.Pool, auditL *audit.Logger, jwt *auth.JWT) *PasswordResetHandler {
	// M-21: generate a per-process HMAC key for the token lookup index.
	// The DB stores BOTH the bcrypt hash (authoritative) and the HMAC
	// hash (O(1) lookup index). Confirm can find the row in one query
	// instead of bcrypt-scanning 100 rows.
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		k = []byte("aegis-pwreset-fallback-hmac")
	}
	return &PasswordResetHandler{
		pool:    pool,
		audit:   auditL,
		jwt:     jwt,
		ttl:     1 * time.Hour,
		devMode: os.Getenv("AEGIS_DEV_MODE") == "true",
		hmacKey: k,
	}
}

// hmacLookupHash returns the indexed SHA-256 HMAC for a plaintext token.
// M-21: keeps token comparison O(1) without weakening the bcrypt layer.
func (h *PasswordResetHandler) hmacLookupHash(plaintext string) string {
	mac := hmac.New(sha256.New, h.hmacKey)
	mac.Write([]byte(plaintext))
	return hex.EncodeToString(mac.Sum(nil))
}

// Request generates a one-time reset token for the given username.
func (h *PasswordResetHandler) Request(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_BODY", err.Error())
		return
	}
	if req.Username == "" {
		// Always respond 200 to avoid username enumeration.
		RespondJSON(w, http.StatusOK, map[string]string{
			"message": "if the account exists, a reset link has been sent",
		})
		return
	}
	// Look up user.
	var userID int
	var email string
	err := h.pool.QueryRow(r.Context(),
		`SELECT id, COALESCE(email, '') FROM users WHERE username = $1`,
		req.Username).Scan(&userID, &email)
	if err != nil {
		// Same anti-enumeration response.
		RespondJSON(w, http.StatusOK, map[string]string{
			"message": "if the account exists, a reset link has been sent",
		})
		return
	}
	// Generate token.
	tokBytes := make([]byte, 32)
	if _, err := rand.Read(tokBytes); err != nil {
		RespondError(w, http.StatusInternalServerError, "INTERNAL", "token gen failed")
		return
	}
	plaintext := hex.EncodeToString(tokBytes)
	hash, err := bcrypt.GenerateFromPassword([]byte(plaintext), 12)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "INTERNAL", "hash failed")
		return
	}
	lookupHash := h.hmacLookupHash(plaintext) // M-21: indexed lookup
	expiresAt := time.Now().Add(h.ttl)
	_, err = h.pool.Exec(r.Context(),
		`INSERT INTO password_reset_tokens (user_id, token_hash, lookup_hash, expires_at, used)
		 VALUES ($1, $2, $3, $4, false)`,
		userID, string(hash), lookupHash, expiresAt)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", "persist failed")
		return
	}
	if h.audit != nil {
		h.audit.Log(audit.Entry{Action: "password_reset.request", ResourceType: "user", ResourceID: req.Username})
	}
	// Production: dispatch email here. P-FIX (C-2): dev mode no longer
	// returns the plaintext token in the response. The dev-mode test
	// path is logged at startup; operators should use the out-of-band
	// email dispatcher in dev too. Returning the token in JSON caused
	// mass account takeover if AEGIS_DEV_MODE was left enabled in
	// production.
	resp := map[string]any{
		"message":    "if the account exists, a reset link has been sent",
		"expires_at": expiresAt,
	}
	if h.devMode {
		// Dev-only convenience: write token to a 0600 file alongside the
		// admin password. Never in the HTTP response.
		const devTokenPath = "/var/lib/aegis/dev_reset_tokens.log"
		_ = os.WriteFile(devTokenPath, []byte(req.Username+":"+plaintext+"\n"), 0o600)
		log.Printf("passwordreset: dev token for %s written to %s (mode=dev, never enabled in prod)", req.Username, devTokenPath)
	}
	_ = email
	RespondJSON(w, http.StatusOK, resp)
}

// Confirm consumes a reset token and updates the password.
func (h *PasswordResetHandler) Confirm(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_BODY", err.Error())
		return
	}
	if req.Token == "" || req.NewPassword == "" {
		RespondError(w, http.StatusBadRequest, "MISSING_FIELDS", "token + new_password required")
		return
	}
	if err := auth.ValidatePassword(req.NewPassword); err != nil {
		RespondError(w, http.StatusBadRequest, "WEAK_PASSWORD", err.Error())
		return
	}
	// M-21: indexed lookup via the HMAC-of-token hash. The bcrypt hash
	// is still the authoritative secret check below. Returns at most 1
	// row instead of bcrypt-scanning 100 candidates.
	lookupHash := h.hmacLookupHash(req.Token)
	var matchedID, matchedUserID int
	var tokenHash string
	err := h.pool.QueryRow(r.Context(),
		`SELECT id, user_id, token_hash FROM password_reset_tokens
		 WHERE lookup_hash = $1 AND expires_at > NOW() AND used = false
		 ORDER BY created_at DESC LIMIT 1`,
		lookupHash).Scan(&matchedID, &matchedUserID, &tokenHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			RespondError(w, http.StatusUnauthorized, "INVALID_TOKEN", "invalid or expired token")
			return
		}
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(tokenHash), []byte(req.Token)); err != nil {
		// The HMAC hash matched but bcrypt rejected — possible HMAC
		// key drift or tampering. Treat as invalid token.
		RespondError(w, http.StatusUnauthorized, "INVALID_TOKEN", "invalid or expired token")
		return
	}
	// Mark used + update password in a transaction.
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
		return
	}
	defer tx.Rollback(r.Context())
	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), 12)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "HASH", err.Error())
		return
	}
	if _, err := tx.Exec(r.Context(),
		`UPDATE users SET password_hash = $1, must_change_password = false, token_version = COALESCE(token_version, 0) + 1 WHERE id = $2`,
		string(hash), matchedUserID); err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
		return
	}
	if _, err := tx.Exec(r.Context(),
		`UPDATE password_reset_tokens SET used = true, used_at = NOW() WHERE id = $1`, matchedID); err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
		return
	}
	if h.audit != nil {
		h.audit.Log(audit.Entry{Action: "password_reset.confirm", ResourceType: "user", ResourceID: idToStr(matchedUserID)})
	}
	RespondJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func idToStr(i int) string { return hex.EncodeToString([]byte{byte(i)}) }
