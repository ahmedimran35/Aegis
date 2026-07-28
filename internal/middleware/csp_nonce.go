package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync/atomic"
)

// CSPNonceConfig configures CSP nonce injection.
type CSPNonceConfig struct {
	Enabled bool
}

// DefaultCSPNonceConfig returns production defaults.
func DefaultCSPNonceConfig() CSPNonceConfig {
	return CSPNonceConfig{Enabled: true}
}

// CSPNonceMiddleware injects CSP nonces into error pages.
type CSPNonceMiddleware struct {
	enabled int32
}

// NewCSPNonceMiddleware creates a CSP nonce middleware.
func NewCSPNonceMiddleware(cfg CSPNonceConfig) *CSPNonceMiddleware {
	m := &CSPNonceMiddleware{}
	if cfg.Enabled {
		m.enabled = 1
	}
	return m
}

// Stats returns a snapshot.
func (m *CSPNonceMiddleware) Stats() map[string]interface{} {
	return map[string]interface{}{
		"enabled": atomic.LoadInt32(&m.enabled) == 1,
	}
}

// Middleware returns HTTP middleware that injects CSP nonce headers.
func (m *CSPNonceMiddleware) Middleware(next http.Handler) http.Handler {
	if atomic.LoadInt32(&m.enabled) == 0 {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := generateNonce()
		r = r.WithContext(context.WithValue(r.Context(), CSPNonceContextKey, nonce))
		if w.Header().Get("Content-Security-Policy") == "" {
			// P-FIX: the previous CSP was missing style-src, img-src,
			// font-src, connect-src, frame-ancestors, base-uri etc. which
			// caused the browser to reject the bundled CSS file from
			// Vite (the link tag has no nonce). Now the CSP includes
			// 'unsafe-inline' for style-src and a full set of
			// directives so the dashboard renders normally.
			w.Header().Set("Content-Security-Policy", fmt.Sprintf(
				"default-src 'self'; "+
					"script-src 'self' 'nonce-%s'; "+
					"style-src 'self' 'unsafe-inline'; "+
					"img-src 'self' data:; "+
					"font-src 'self' data:; "+
					"connect-src 'self' wss:; "+
					"object-src 'none'; "+
					"base-uri 'self'; "+
					"form-action 'self'; "+
					"frame-ancestors 'self'; "+
					"manifest-src 'self'; "+
					"worker-src 'self'",
				nonce))
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

var CSPNonceContextKey = struct{}{}

// CSPNonceFromContextValue extracts a CSP nonce from a context.
func CSPNonceFromContextValue(ctx context.Context) string {
	if v := ctx.Value(CSPNonceContextKey); v != nil {
		return v.(string)
	}
	return ""
}

// CSPNonceFromContext extracts the nonce from request context.
func CSPNonceFromContext(r *http.Request) string {
	if r == nil {
		return ""
	}
	return CSPNonceFromContextValue(r.Context())
}

func generateNonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
