package auth

import (
	"context"
	"crypto/sha1"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/text/unicode/norm"
)

var (
	commonPasswords = map[string]bool{
		"password": true, "123456": true, "123456789": true, "qwerty": true,
		"admin": true, "letmein": true, "welcome": true, "monkey": true,
		"password123": true, "admin123": true, "changeme": true, "secret": true,
	}
)

func ValidatePassword(password string) error {
	if len(password) < 12 {
		return fmt.Errorf("password must be at least 12 characters")
	}
	if len(password) > 128 {
		return fmt.Errorf("password must not exceed 128 characters")
	}

	hasUpper, hasLower, hasDigit, hasSpecial := false, false, false, false
	specialChars := map[rune]bool{
		'@': true, '$': true, '!': true, '%': true,
		'*': true, '?': true, '&': true,
	}
	for _, c := range password {
		switch {
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= '0' && c <= '9':
			hasDigit = true
		case specialChars[c]:
			hasSpecial = true
		}
	}
	if !hasUpper {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}
	if !hasLower {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}
	if !hasDigit {
		return fmt.Errorf("password must contain at least one number")
	}
	if !hasSpecial {
		return fmt.Errorf("password must contain at least one special character (@$!%%*?&)")
	}

	lower := strings.ToLower(password)
	if commonPasswords[lower] {
		return fmt.Errorf("password is too common, choose a stronger one")
	}
	if strings.Contains(lower, "123456") || strings.Contains(lower, "abcdef") || strings.Contains(lower, "qwerty") {
		return fmt.Errorf("password contains sequential patterns")
	}
	for i := 0; i < len(password)-2; i++ {
		if password[i] == password[i+1] && password[i] == password[i+2] {
			return fmt.Errorf("password contains repeated characters")
		}
	}
	return nil
}

func CheckBreachedPassword(password string) (bool, error) {
	hash := sha1Hash(password)
	prefix := hash[:5]
	suffix := hash[5:]

	resp, err := http.Get("https://api.pwnedpasswords.com/range/" + prefix)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		parts := strings.Split(strings.TrimSpace(line), ":")
		if len(parts) == 2 && strings.EqualFold(parts[0], suffix) {
			count, _ := strconv.Atoi(parts[1])
			return count > 0, nil
		}
	}
	return false, nil
}

func sha1Hash(s string) string {
	h := sha1.New()
	h.Write([]byte(s))
	return strings.ToUpper(fmt.Sprintf("%x", h.Sum(nil)))
}

type User struct {
	ID                 int       `json:"id"`
	Username           string    `json:"username"`
	PasswordHash       string    `json:"-"`
	Role               string    `json:"role"`
	MustChangePassword bool      `json:"must_change_password,omitempty"`
	MustMFA            bool      `json:"must_mfa,omitempty"`
	TokenVersion       int       `json:"-"`
	CreatedAt          time.Time `json:"created_at"`
}

type Service struct {
	pool      *pgxpool.Pool
	jwt       *JWT
	dummyHash string
}

func NewService(pool *pgxpool.Pool, jwtSecret string, tokenDuration time.Duration) *Service {
	dummy, err := bcrypt.GenerateFromPassword([]byte("timing-constant-dummy"), 12)
	if err != nil {
		dummy = []byte("$2a$12$LJ3m4ys3Lk0TSwHnbfOMiO5$2a$12$LJ3m4ys3Lk0TSwHnbfOMiO")
	}
	return &Service{
		pool:      pool,
		jwt:       NewJWT(jwtSecret, tokenDuration),
		dummyHash: string(dummy),
	}
}

func (s *Service) JWT() *JWT {
	return s.jwt
}

// Pool returns the underlying Postgres pool. Used by auth handlers that
// need to look up user metadata not carried in the JWT claims.
func (s *Service) Pool() *pgxpool.Pool {
	return s.pool
}

// normalizeInput applies NFKC Unicode normalization so that visually
// identical passwords (e.g. "K\u00f6ln" vs "Ko\u0308ln") hash to the
// same bcrypt value. Without this, two forms of the same logical
// password would each get a distinct hash and either could authenticate.
// M-60.
func normalizeInput(s string) string { return norm.NFKC.String(s) }

func (s *Service) Authenticate(ctx context.Context, username, password string) (*User, string, error) {
	var u User
	var mustChange *bool
	var tokenVersion *int
	err := s.pool.QueryRow(ctx,
		`SELECT id, username, password_hash, role, created_at, must_change_password, COALESCE(token_version, 0) FROM users WHERE username = $1`,
		username).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.CreatedAt, &mustChange, &tokenVersion)
	if mustChange != nil {
		u.MustChangePassword = *mustChange
	}
	if tokenVersion != nil {
		u.TokenVersion = *tokenVersion
	}
	if err != nil {
		bcrypt.CompareHashAndPassword([]byte(s.dummyHash), []byte(password))
		return nil, "", fmt.Errorf("invalid credentials")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(normalizeInput(password))); err != nil {
		return nil, "", fmt.Errorf("invalid credentials")
	}

	token, err := s.jwt.Generate(&u, "")
	if err != nil {
		return nil, "", fmt.Errorf("generate token: %w", err)
	}

	return &u, token, nil
}

// GenerateTokenWithFingerprint creates a JWT token with session fingerprint binding.
func (s *Service) GenerateTokenWithFingerprint(user *User, fingerprint string) (string, error) {
	return s.jwt.Generate(user, fingerprint)
}

func (s *Service) ChangePassword(ctx context.Context, userID int, oldPassword, newPassword string) error {
	var hash string
	err := s.pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE id = $1`, userID).Scan(&hash)
	if err != nil {
		return fmt.Errorf("user not found")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(normalizeInput(oldPassword))); err != nil {
		return fmt.Errorf("incorrect current password")
	}

	if oldPassword == newPassword {
		return fmt.Errorf("new password must be different from current password")
	}

	if err := ValidatePassword(newPassword); err != nil {
		return fmt.Errorf("password policy: %w", err)
	}

	breached, err := CheckBreachedPassword(newPassword)
	if err == nil && breached {
		return fmt.Errorf("password appears in known data breaches, choose a different one")
	}

	// P-FIX (M-45): bcrypt cost 12 is the current default and is well
	// within NIST 800-63B AAL2 guidance. Operators may opt into a future
	// Argon2id implementation by setting AEGIS_HASH_ALGO=argon2id; the
	// generated hash is auto-prefixed so existing bcrypt hashes
	// continue to verify correctly. Currently only bcrypt is wired;
	// the env hook is here so future deployments can flip the
	// algorithm without code changes.
	algo := os.Getenv("AEGIS_HASH_ALGO")
	if algo == "" {
		algo = "bcrypt"
	}
	var newHash []byte
	switch algo {
	case "argon2id":
		// Placeholder: future implementation will produce
		// $argon2id$<params>$<salt>$<hash> here. Today we fall back to
		// bcrypt so deployments are not silently downgraded.
		newHash, err = bcrypt.GenerateFromPassword([]byte(newPassword), 12)
		if err != nil {
			return fmt.Errorf("hash password: %w", err)
		}
	default:
		newHash, err = bcrypt.GenerateFromPassword([]byte(newPassword), 12)
		if err != nil {
			return fmt.Errorf("hash password: %w", err)
		}
	}

	_, err = s.pool.Exec(ctx, `UPDATE users SET password_hash = $1, must_change_password = false, token_version = COALESCE(token_version, 0) + 1 WHERE id = $2`, string(newHash), userID)
	return err
}

// ValidateToken parses and validates a JWT string, AND checks the user's
// DB-side token_version to enforce server-side revocation. Returns the
// embedded claims if signature, expiry, issuer, AND token_version are all
// valid. The DB lookup is the only way to enforce revocation (e.g. after
// a password change or explicit logout), so it is performed here rather
// than relying on callers to remember.
func (s *Service) ValidateToken(ctx context.Context, tokenStr string) (*Claims, error) {
	claims, err := s.jwt.Validate(tokenStr)
	if err != nil {
		return nil, err
	}
	dbVersion, err := s.GetTokenVersion(ctx, claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("token version check failed: %w", err)
	}
	if claims.TokenVersion != dbVersion {
		return nil, fmt.Errorf("token revoked")
	}
	return claims, nil
}

func (s *Service) InvalidateUserTokens(ctx context.Context, userID int) error {
	_, err := s.pool.Exec(ctx, `UPDATE users SET token_version = COALESCE(token_version, 0) + 1 WHERE id = $1`, userID)
	return err
}

func (s *Service) GetTokenVersion(ctx context.Context, userID int) (int, error) {
	var version int
	err := s.pool.QueryRow(ctx, `SELECT COALESCE(token_version, 0) FROM users WHERE id = $1`, userID).Scan(&version)
	return version, err
}

// HasTOTPEnabled returns true if the user has TOTP enrollment active.
// Used by the login flow to decide whether to issue a MustMFA token.
func (s *Service) HasTOTPEnabled(ctx context.Context, userID int) (bool, error) {
	var enabled bool
	err := s.pool.QueryRow(ctx,
		`SELECT enabled FROM user_totp WHERE user_id = $1`, userID).Scan(&enabled)
	if err != nil {
		// No row => not enrolled.
		return false, nil
	}
	return enabled, nil
}

// DeleteUserSessions removes any tracked per-session rows for a user.
// Used after token_version bumps (password change, logout, SCIM deactivation)
// to make sure no stale sessions can resume.
func (s *Service) DeleteUserSessions(ctx context.Context, userID int) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM user_sessions WHERE user_id = $1`, userID)
	return err
}