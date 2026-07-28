package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type contextKey string

const claimsKey contextKey = "claims"

// ClaimsFromContext extracts JWT claims from request context.
func ClaimsFromContext(ctx context.Context) *Claims {
	v, _ := ctx.Value(claimsKey).(*Claims)
	return v
}

// ContextWithClaims adds JWT claims to context.
func ContextWithClaims(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, claimsKey, claims)
}

// Claims holds JWT token claims.
type Claims struct {
	UserID             int    `json:"user_id"`
	Username           string `json:"username"`
	Role               string `json:"role"`
	TokenVersion       int    `json:"token_version"`
	MustChangePassword bool   `json:"must_change_password,omitempty"`
	// MustMFA is true on a freshly-issued login token when the user has
	// TOTP enabled. The middleware rejects any request other than the
	// MFA verify / me endpoints until MustMFA is cleared by a successful
	// verify or recovery.
	MustMFA            bool   `json:"must_mfa,omitempty"`
	SessionFingerprint string `json:"session_fp,omitempty"`
	jwt.RegisteredClaims
}

// JWT handles token generation and validation.
type JWT struct {
	secret   []byte
	duration time.Duration
}

// NewJWT creates a new JWT handler.
func NewJWT(secret string, duration time.Duration) *JWT {
	return &JWT{
		secret:   []byte(secret),
		duration: duration,
	}
}

// Generate creates a new JWT token for a user.
func (j *JWT) Generate(user *User, sessionFingerprint string) (string, error) {
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", fmt.Errorf("generate jti: %w", err)
	}

	claims := &Claims{
		UserID:              user.ID,
		Username:            user.Username,
		Role:                user.Role,
		TokenVersion:        user.TokenVersion,
			MustChangePassword:  user.MustChangePassword,
			MustMFA:             user.MustMFA,
			SessionFingerprint:  sessionFingerprint,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        hex.EncodeToString(jti),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(j.duration)),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "aegis",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(j.secret)
}

// Validate parses and validates a JWT token string.
func (j *JWT) Validate(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return j.secret, nil
	}, jwt.WithIssuer("aegis"))
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}
