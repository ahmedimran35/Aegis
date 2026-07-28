// Package api: real TOTP (RFC 6238) implementation.
//
// TOTP enroll/verify/recover with per-user encrypted secret storage.
// Secrets are stored AES-GCM-encrypted in the database. Recovery codes
// are one-time-use bcrypt-hashed strings generated at enrollment time.
//
// Algorithm:
//   1. Enrollment generates a 20-byte secret, base32-encodes it, returns
//      a otpauth:// URI and a QR code (PNG) for the authenticator app.
//   2. Verify accepts a 6-digit code; uses TOTP-SHA1 with 30s step and
//      1-step skew tolerance per RFC 6238 §5.2.
//   3. Recovery codes are 8 6-digit codes generated at enrollment; any
//      unused code can replace a TOTP code. Codes are bcrypt-hashed.
package api

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"image/png"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/user/waf/internal/audit"
	"github.com/user/waf/internal/auth"
	"golang.org/x/crypto/bcrypt"
)

// TOTPHandler is the live TOTP enrollment/verify/recover handler.
type TOTPHandler struct {
	pool        *pgxpool.Pool
	rdb         interface{} // *redis.Client; kept as interface{} for compatibility with nil tests
	audit       *audit.Logger
	jwtService  *auth.JWT
	cookieFn    func(http.ResponseWriter, *http.Request, string)
	issuer      string
	maxAttempts int
	lockDur     time.Duration
	encKey      []byte
}

// NewTOTPHandler creates a TOTP handler. rdb is used for the per-user
// failed-attempt counter (H-7/H-10). It is safe to pass nil for tests.
func NewTOTPHandler(pool *pgxpool.Pool, rdb *redis.Client, auditL *audit.Logger, encKey []byte, jwtService *auth.JWT, cookieFn func(http.ResponseWriter, *http.Request, string)) *TOTPHandler {
	if len(encKey) < 32 {
		// P-FIX (H-6): hard-fail if TOTP AES key is too short, and never
		// silently fall back to the JWT secret. The previous behavior
		// padded short keys with zeros which is insecure.
		panic("NewTOTPHandler: AEGIS_TOTP_KEY must be >= 32 bytes")
	}
	return &TOTPHandler{
		pool:        pool,
		rdb:         rdb,
		audit:       auditL,
		jwtService:  jwtService,
		cookieFn:    cookieFn,
		issuer:      "Aegis",
		maxAttempts: 10,
		lockDur:     5 * time.Minute,
		encKey:      encKey,
	}
}

// Enroll generates a new TOTP secret for the authenticated user.
//
// P-FIX (H-17): the default algorithm is now SHA-256 (was SHA-1). All
// popular authenticator apps support SHA-256; the legacy SHA-1 path is
// retained only for backward compatibility with previously enrolled
// secrets (verifyTOTP branches on algorithm).
func (h *TOTPHandler) Enroll(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		RespondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "auth required")
		return
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		RespondError(w, http.StatusInternalServerError, "INTERNAL", "secret generation failed")
		return
	}
	cipher, err := encryptSecret(secret, h.encKey)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "INTERNAL", "encrypt failed")
		return
	}
	_, err = h.pool.Exec(r.Context(),
		`INSERT INTO user_totp (user_id, secret_enc, enabled, created_at)
		 VALUES ($1, $2, false, NOW())
		 ON CONFLICT (user_id) DO UPDATE SET secret_enc = EXCLUDED.secret_enc, enabled = false, created_at = NOW()`,
		claims.UserID, cipher)
	if err != nil {
		log.Printf("totp: persist: %v", err)
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", "persist failed")
		return
	}
	secretB32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
	uri := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA256&digits=6&period=30",
		url.PathEscape(h.issuer), url.PathEscape(claims.Username), secretB32, url.QueryEscape(h.issuer))
	qrCode, err := qr.Encode(uri, qr.M, qr.Auto)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "QR_ERROR", err.Error())
		return
	}
	qrCode, err = barcode.Scale(qrCode, 256, 256)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "QR_SCALE", err.Error())
		return
	}
	var pngBuf bytes.Buffer
	if err := png.Encode(&pngBuf, qrCode); err != nil {
		RespondError(w, http.StatusInternalServerError, "PNG_ENCODE", err.Error())
		return
	}
	RespondJSON(w, http.StatusOK, map[string]any{
		"secret":      secretB32,
		"otpauth_uri": uri,
		"qr_png_b64":  base64.StdEncoding.EncodeToString(pngBuf.Bytes()),
		"issuer":      h.issuer,
		"algorithm":   "SHA256",
		"digits":      6,
		"period":      30,
	})
}

// ConfirmEnroll verifies the first TOTP code and marks the secret enabled.
func (h *TOTPHandler) ConfirmEnroll(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		RespondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "auth required")
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_BODY", err.Error())
		return
	}
	secret, enabled, err := h.loadSecret(r.Context(), claims.UserID)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
		return
	}
	if enabled {
		RespondError(w, http.StatusConflict, "ALREADY_ENABLED", "TOTP already enabled")
		return
	}
	if !verifyTOTP(secret, req.Code, time.Now(), 1) {
		RespondError(w, http.StatusBadRequest, "INVALID_CODE", "code did not match")
		return
	}
	codes, hashes, err := generateRecoveryCodes(8)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "RECOVERY", err.Error())
		return
	}
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
		return
	}
	defer tx.Rollback(r.Context())
	if _, err := tx.Exec(r.Context(),
		`UPDATE user_totp SET enabled = true WHERE user_id = $1`, claims.UserID); err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
		return
	}
	if _, err := tx.Exec(r.Context(),
		`DELETE FROM user_totp_recovery WHERE user_id = $1`, claims.UserID); err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
		return
	}
	for _, hh := range hashes {
		if _, err := tx.Exec(r.Context(),
			`INSERT INTO user_totp_recovery (user_id, code_hash, used) VALUES ($1, $2, false)`,
			claims.UserID, hh); err != nil {
			RespondError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
			return
		}
	}
	if err := tx.Commit(r.Context()); err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
		return
	}
	if h.audit != nil {
		h.audit.Log(audit.Entry{Action: "totp.enroll.confirm", ResourceType: "user", ResourceID: fmt.Sprintf("%d", claims.UserID)})
	}
	RespondJSON(w, http.StatusOK, map[string]any{
		"enabled":        true,
		"recovery_codes": codes,
		"message":        "TOTP enabled. Store the recovery codes safely — they will not be shown again.",
	})
}

// Verify is invoked by the client after a successful password login when
// the user has TOTP enrolled. It is reached via AuthMiddleware, which
// permits the request only because the caller's JWT carries must_mfa=true.
//
// On success, we revoke the pre-existing session (token_version bump,
// H-10) and issue a fresh JWT with must_mfa=false.
//
// (H-7/H-10) Per-user attempt counter: more than maxAttempts wrong
// codes within lockDur results in a 429 until the lock expires.
func (h *TOTPHandler) Verify(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil || !claims.MustMFA {
		RespondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "pre-MFA token required")
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_BODY", err.Error())
		return
	}
	if req.Code == "" {
		RespondError(w, http.StatusBadRequest, "MISSING_FIELDS", "code required")
		return
	}
	userID := claims.UserID
	if h.checkTOTPLockout(r, userID) {
		RespondError(w, http.StatusTooManyRequests, "TOTP_LOCKED", "too many failed TOTP attempts; try again later")
		return
	}
	secret, enabled, err := h.loadSecret(r.Context(), userID)
	if err != nil || !enabled {
		RespondError(w, http.StatusUnauthorized, "INVALID_CODE", "invalid code")
		return
	}
	if !verifyTOTP(secret, req.Code, time.Now(), 1) {
		h.recordTOTPFailure(r, userID)
		RespondError(w, http.StatusUnauthorized, "INVALID_CODE", "invalid code")
		return
	}
	h.clearTOTPFailures(r, userID)
	if err := h.bumpTokenVersion(r, userID); err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
		return
	}
	tv, _ := h.readTokenVersion(r, userID)
	u := &auth.User{ID: userID, Username: claims.Username, Role: claims.Role, TokenVersion: tv, MustMFA: false}
	tok, err := h.jwtService.Generate(u, "")
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "TOKEN_ERROR", err.Error())
		return
	}
	if h.cookieFn != nil {
		h.cookieFn(w, r, tok)
	}
	if h.audit != nil {
		h.audit.Log(audit.Entry{Action: "totp.verify", ResourceType: "user", ResourceID: claims.Username})
	}
	RespondJSON(w, http.StatusOK, map[string]any{"ok": true, "user": u})
}

// Recover accepts a recovery code in place of a TOTP code. This is the
// only path that can be reached by a user who has lost their authenticator
// device, so it remains unauthenticated. On success it issues a fresh
// session token (H-9/H-10).
func (h *TOTPHandler) Recover(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username     string `json:"username"`
		RecoveryCode string `json:"recovery_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_BODY", err.Error())
		return
	}
	if req.Username == "" || req.RecoveryCode == "" {
		RespondError(w, http.StatusBadRequest, "MISSING_FIELDS", "username + recovery_code required")
		return
	}
	if h.checkTOTPLockout(r, hashUsername(req.Username)) {
		RespondError(w, http.StatusTooManyRequests, "TOTP_LOCKED", "too many failed TOTP attempts; try again later")
		return
	}
	var userID int
	var role string
	if err := h.pool.QueryRow(r.Context(),
		`SELECT id, role FROM users WHERE username = $1`, req.Username).
		Scan(&userID, &role); err != nil {
		RespondError(w, http.StatusUnauthorized, "INVALID_CODE", "invalid recovery code")
		return
	}
	rows, err := h.pool.Query(r.Context(),
		`SELECT id, code_hash FROM user_totp_recovery
		 WHERE user_id = $1 AND used = false`, userID)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
		return
	}
	defer rows.Close()
	matched := 0
	for rows.Next() {
		var id int
		var hash string
		if err := rows.Scan(&id, &hash); err != nil {
			continue
		}
		if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.RecoveryCode)); err == nil {
			if _, err := h.pool.Exec(r.Context(),
				`UPDATE user_totp_recovery SET used = true, used_at = NOW() WHERE id = $1`, id); err != nil {
				RespondError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
				return
			}
			matched = id
			break
		}
	}
	if matched == 0 {
		h.recordTOTPFailure(r, hashUsername(req.Username))
		RespondError(w, http.StatusUnauthorized, "INVALID_CODE", "invalid recovery code")
		return
	}
	h.clearTOTPFailures(r, hashUsername(req.Username))
	if err := h.bumpTokenVersion(r, userID); err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
		return
	}
	tv, _ := h.readTokenVersion(r, userID)
	u := &auth.User{ID: userID, Username: req.Username, Role: role, TokenVersion: tv, MustMFA: false}
	tok, err := h.jwtService.Generate(u, "")
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "TOKEN_ERROR", err.Error())
		return
	}
	if h.cookieFn != nil {
		h.cookieFn(w, r, tok)
	}
	if h.audit != nil {
		h.audit.Log(audit.Entry{Action: "totp.recover", ResourceType: "user", ResourceID: req.Username})
	}
	RespondJSON(w, http.StatusOK, map[string]any{"ok": true, "user": u})
}

// RegenerateRecoveryCodes issues a new set of recovery codes, invalidating
// any existing ones. Auth required.
func (h *TOTPHandler) RegenerateRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		RespondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "auth required")
		return
	}
	codes, hashes, err := generateRecoveryCodes(8)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "GEN", err.Error())
		return
	}
	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
		return
	}
	defer tx.Rollback(r.Context())
	if _, err := tx.Exec(r.Context(),
		`DELETE FROM user_totp_recovery WHERE user_id = $1`, claims.UserID); err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
		return
	}
	for _, hh := range hashes {
		if _, err := tx.Exec(r.Context(),
			`INSERT INTO user_totp_recovery (user_id, code_hash, used) VALUES ($1, $2, false)`,
			claims.UserID, hh); err != nil {
			RespondError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
			return
		}
	}
	if err := tx.Commit(r.Context()); err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
		return
	}
	if h.audit != nil {
		h.audit.Log(audit.Entry{Action: "totp.recovery.regen", ResourceType: "user", ResourceID: fmt.Sprintf("%d", claims.UserID)})
	}
	RespondJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

// --- TOTP primitives ---

// encryptSecret encrypts a TOTP secret using AES-GCM with the encKey.
func encryptSecret(plain, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nil, nonce, plain, nil)
	out := append(nonce, ct...)
	return base64.StdEncoding.EncodeToString(out), nil
}

// decryptSecret reverses encryptSecret.
func decryptSecret(cipherText string, key []byte) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(raw) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}

// verifyTOTP returns true if `code` matches the TOTP value derived from
// `secret` at time `t`, allowing ±skew steps of 30s. Implements RFC 6238.
//
// P-FIX (H-17): secrets provisioned today default to 32 bytes with HMAC-
// SHA256. Older enrollments using 20-byte SHA-1 secrets continue to work
// (the algorithm is selected by secret length).
func verifyTOTP(secret []byte, code string, t time.Time, skew int) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}
	var input uint32
	if _, err := fmt.Sscanf(code, "%06d", &input); err != nil {
		return false
	}
	counter := uint64(t.Unix()) / 30
	for i := -skew; i <= skew; i++ {
		gen := totpAt(secret, counter+uint64(int64(i)))
		if uint32(subtle.ConstantTimeCompare(uint32ToBytes(gen), uint32ToBytes(input))) == 1<<32-1 {
			return true
		}
	}
	return false
}

// totpAt computes the 6-digit TOTP value for the given counter. Hash
// algorithm is chosen by secret length: >= 32 bytes ⇒ SHA-256 (preferred,
// H-17); otherwise the original HMAC-SHA1 path is used for backward
// compatibility with previously enrolled secrets.
func totpAt(secret []byte, counter uint64) uint32 {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)
	var sum []byte
	if len(secret) >= 32 {
		h := hmac.New(sha256.New, secret)
		h.Write(buf)
		sum = h.Sum(nil)
	} else {
		h := hmac.New(sha1.New, secret)
		h.Write(buf)
		sum = h.Sum(nil)
	}
	offset := sum[len(sum)-1] & 0x0F
	binary := (uint32(sum[offset])&0x7F)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	return binary % 1_000_000
}

func uint32ToBytes(n uint32) []byte {
	return []byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}

// alphanumericAlphabet is the set of unambiguous alphanumeric characters
// used by recovery codes. We exclude I/O/0/1 to keep codes easy to copy.
// P-FIX (H-8): 16 chars × ~31-symbol alphabet => ~80 bits of entropy per
// code, which is well above the 64-bit threshold for one-time tokens.
const alphanumericAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// generateRecoveryCodes returns (plaintext, bcrypt-hash) pairs.
//
// P-FIX (H-8): previous codes were two 6-digit decimals (10^12 search
// space per code) which is too narrow given modern guess rates. We now use
// 16 alphanumeric characters from a 32-symbol alphabet, giving ~80 bits of
// entropy per code. Codes are formatted as XXXX-XXXX-XXXX-XXXX for human
// readability and bcrypt cost is 12 to match the rest of the auth surface.
func generateRecoveryCodes(n int) (codes []string, hashes []string, err error) {
	for i := 0; i < n; i++ {
		buf := make([]byte, 16)
		codeBytes := make([]byte, 16)
		if _, err := rand.Read(buf); err != nil {
			return nil, nil, err
		}
		// Map each random byte to an alphabet character via modulo. The
		// alphabet length (32) divides 256 evenly so the modulo bias is
		// negligible (<1%).
		for j, b := range buf {
			codeBytes[j] = alphanumericAlphabet[int(b)%len(alphanumericAlphabet)]
		}
		// Format as XXXX-XXXX-XXXX-XXXX for human readability.
		raw := string(codeBytes)
		code := raw[0:4] + "-" + raw[4:8] + "-" + raw[8:12] + "-" + raw[12:16]
		// Bcrypt cost bumped to 12 for consistency with Login/Users.
		hash, err := bcrypt.GenerateFromPassword([]byte(code), 12)
		if err != nil {
			return nil, nil, err
		}
		codes = append(codes, code)
		hashes = append(hashes, string(hash))
	}
	return codes, hashes, nil
}


// loadSecret returns the decrypted TOTP secret + enabled flag for a user.
func (h *TOTPHandler) loadSecret(ctx context.Context, userID int) ([]byte, bool, error) {
	var cipherText string
	var enabled bool
	if err := h.pool.QueryRow(ctx,
		`SELECT secret_enc, enabled FROM user_totp WHERE user_id = $1`, userID).
		Scan(&cipherText, &enabled); err != nil {
		return nil, false, err
	}
	secret, err := decryptSecret(cipherText, h.encKey)
	if err != nil {
		return nil, false, err
	}
	return secret, enabled, nil
}

// --- H-7/H-10: per-user TOTP failure tracking -----------------------------

func hashUsername(u string) int { return int(crc32.ChecksumIEEE([]byte(u))) }

func (h *TOTPHandler) totpAttemptsKey(id int) string {
	return fmt.Sprintf("totp:fail:%d", id)
}

func (h *TOTPHandler) checkTOTPLockout(r *http.Request, id int) bool {
	rdb, ok := h.rdb.(*redis.Client)
	if !ok || rdb == nil {
		return false
	}
	ctx := r.Context()
	v, err := rdb.Get(ctx, h.totpAttemptsKey(id)).Int()
	if err != nil {
		return false
	}
	return v >= h.maxAttempts
}

func (h *TOTPHandler) recordTOTPFailure(r *http.Request, id int) {
	rdb, ok := h.rdb.(*redis.Client)
	if !ok || rdb == nil {
		return
	}
	ctx := r.Context()
	pipe := rdb.Pipeline()
	pipe.Incr(ctx, h.totpAttemptsKey(id))
	pipe.Expire(ctx, h.totpAttemptsKey(id), h.lockDur)
	pipe.Exec(ctx)
}

func (h *TOTPHandler) clearTOTPFailures(r *http.Request, id int) {
	rdb, ok := h.rdb.(*redis.Client)
	if !ok || rdb == nil {
		return
	}
	rdb.Del(r.Context(), h.totpAttemptsKey(id))
}

// bumpTokenVersion rotates the user's token_version (H-9/H-10).
func (h *TOTPHandler) bumpTokenVersion(r *http.Request, userID int) error {
	_, err := h.pool.Exec(r.Context(),
		`UPDATE users SET token_version = COALESCE(token_version, 0) + 1 WHERE id = $1`, userID)
	return err
}

// readTokenVersion returns the current token_version for userID.
func (h *TOTPHandler) readTokenVersion(r *http.Request, userID int) (int, error) {
	var v int
	err := h.pool.QueryRow(r.Context(),
		`SELECT COALESCE(token_version, 0) FROM users WHERE id = $1`, userID).Scan(&v)
	return v, err
}
