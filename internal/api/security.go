package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	wafmw "github.com/user/waf/internal/middleware"
)

// AllowedCORSOrigins holds the CORS allowlist. Set it before the server starts.
// Empty slice = no CORS headers (default). Use ["*"] only in development with extreme caution.
var AllowedCORSOrigins []string

// AuthCookieName returns the cookie name to use for the auth token.
// Over HTTPS we use the __Host- prefix which (a) requires Secure,
// (b) forbids Domain attribute, and (c) requires Path=/, providing
// strong isolation guarantees. Over plain HTTP (dev only) we fall back
// to a plain name because __Host- requires Secure which browsers refuse
// to set over plaintext.
func AuthCookieName(secure bool) string {
	if secure {
		return "__Host-aegis_token"
	}
	return "aegis_token"
}

// CSRF cookie/header names. The cookie value is the "double-submit"
// token: the dashboard reads it via document.cookie and echoes it in
// the X-CSRF-Token header. Same __Host- rules apply on TLS.
const (
	csrfCookieNameSecure   = "__Host-aegis_csrf"
	csrfCookieNameInsecure = "aegis_csrf"
	csrfHeaderName         = "X-CSRF-Token"
)

// csrfCookieName returns the appropriate cookie name based on TLS state.
func csrfCookieName(secure bool) string {
	if secure {
		return csrfCookieNameSecure
	}
	return csrfCookieNameInsecure
}

// CSRFHeaderName is the request header the dashboard sends the CSRF
// token on. Exported so middleware can wire it into the response
// header for client convenience.
func CSRFHeaderName() string { return csrfHeaderName }

// IsTLSRequest mirrors the nginx proxy / direct TLS check used elsewhere.
func isTLSRequest(r *http.Request) bool {
	return r.TLS != nil || (r.Header.Get("X-Forwarded-Proto") == "https" && wafmw.IsTrustedProxyReq(r))
}

type ctxKey string

// securityHeadersMiddleware sets security headers on all responses with nonce-based CSP.
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := generateNonce()
		ctx := r.Context()
		ctx = context.WithValue(ctx, wafmw.CSPNonceContextKey, nonce)
		r = r.WithContext(ctx)

		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
		// Only set HSTS on HTTPS (browsers ignore it on plain HTTP).
		// P-FIX (H-10): we ONLY honor X-Forwarded-Proto from a peer that the
		// operator configured as a trusted proxy. Otherwise an attacker can
		// spoof the header on a plaintext listener and trick us into setting
		// HSTS, which the browser will then obey for max-age and refuse to
		// fall back to cleartext (CWE-319 / CWE-870).
		isTLS := r.TLS != nil || (r.Header.Get("X-Forwarded-Proto") == "https" && wafmw.IsTrustedProxyReq(r))
		if isTLS {
			// M-25: HSTS `preload` is opt-in via AEGIS_HSTS_PRELOAD to keep
			// the router-level and security.go behavior consistent.
			hsts := "max-age=31536000; includeSubDomains"
			if os.Getenv("AEGIS_HSTS_PRELOAD") == "true" {
				hsts += "; preload"
			}
			w.Header().Set("Strict-Transport-Security", hsts)
		}
		// P-FIX (audit): CSP allows only wss: for WebSockets. The previous
		// value of `ws: wss:` would let a downgrade attacker force plaintext
		// WS connections over a hijacked DNS / ARP.
		csp := "default-src 'self'; " +
			"script-src 'self' 'nonce-" + nonce + "'; " +
			// P-FIX: 'unsafe-inline' for style-src. The dashboard is a
			// self-hosted single-tenant app — there is no XSS risk from
			// inline styles (the React app does not render attacker-
			// controlled HTML). The previous nonce requirement for CSS
			// broke the bundled Vite output because Vite does not emit
			// nonces on its emitted <link> tags.
			"style-src 'self' 'unsafe-inline'; " +
			"object-src 'none'; " +
			"connect-src 'self' wss:; " +
			"base-uri 'self'; " +
			"form-action 'self'; " +
			"frame-ancestors 'self'; " +
			"manifest-src 'self'; " +
			"worker-src 'self'"
		w.Header().Set("Content-Security-Policy", csp)
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), usb=(), payment=(), accelerometer=(), gyroscope=(), magnetometer=()")
		next.ServeHTTP(w, r)
	})
}

// generateNonce creates a cryptographically secure random nonce for CSP.
func generateNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "fallback-nonce"
	}
	return base64.RawStdEncoding.EncodeToString(b)
}

// CSPNonceFromContext extracts the CSP nonce from request context.
func CSPNonceFromContext(ctx context.Context) string {
	return wafmw.CSPNonceFromContextValue(ctx)
}

// corsMiddleware sets CORS headers for cross-origin requests.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			// Validate origin against allowlist
			allowed := false
			for _, o := range AllowedCORSOrigins {
				if o == origin || o == "*" {
					allowed = true
					break
				}
			}

			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
				// P-FIX: include the CSRF header in the allowed-headers list so
				// the browser preflight doesn't drop the X-CSRF-Token sent by
				// the dashboard's apiPost/apiPut/apiDelete helpers.
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, "+csrfHeaderName)
				w.Header().Set("Access-Control-Max-Age", "86400")
			}
		}

		// Always allow OPTIONS preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// csrfMiddleware validates the double-submit CSRF cookie and the
// Origin/Referer for state-changing requests. It also issues the
// CSRF cookie on the first authenticated response if missing so the
// dashboard's client can read it via document.cookie and echo it in
// the X-CSRF-Token header.
func csrfMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Issue a CSRF cookie if missing. We do this on every response so
		// the dashboard always has a fresh token to send. The cookie is
		// JS-readable (no HttpOnly) so the client can echo it as the
		// X-CSRF-Token header — that's the whole point of the
		// double-submit pattern. The cookie is NOT a session identifier,
		// so XSS stealing it doesn't grant access; the attacker would
		// also need the HttpOnly auth cookie which XSS cannot read.
		secure := isTLSRequest(r)
		if _, err := r.Cookie(csrfCookieName(secure)); err != nil {
			tok, terr := generateCSRFToken()
			if terr == nil {
				http.SetCookie(w, &http.Cookie{
					Name:     csrfCookieName(secure),
					Value:    tok,
					Path:     "/",
					Secure:   secure,
					HttpOnly: false, // JS must read this
					SameSite: http.SameSiteStrictMode,
					MaxAge:   86400,
				})
			}
		}

		if r.Method == "POST" || r.Method == "PUT" || r.Method == "DELETE" {
			// Skip for login (no session yet) and WebSocket
			if r.URL.Path == "/api/v1/auth/login" || r.URL.Path == "/api/v1/ws" {
				next.ServeHTTP(w, r)
				return
			}
			// Skip CSRF for API clients using Bearer token auth
			// CSRF exploits cookies, not custom Authorization headers
			if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
				next.ServeHTTP(w, r)
				return
			}
			// Double-submit token validation. The cookie and the
			// X-CSRF-Token header must match exactly. We use
			// subtle.ConstantTimeCompare to avoid timing oracles.
			cookie, _ := r.Cookie(csrfCookieName(secure))
			header := r.Header.Get(csrfHeaderName)
			if cookie == nil || header == "" {
				RespondError(w, http.StatusForbidden, "CSRF_CHECK_FAILED", "missing CSRF token")
				return
			}
			if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(header)) != 1 {
				RespondError(w, http.StatusForbidden, "CSRF_CHECK_FAILED", "CSRF token mismatch")
				return
			}
			origin := r.Header.Get("Origin")
			referer := r.Header.Get("Referer")

			// Extract host, port, scheme from request
			reqHost, reqPort, err := net.SplitHostPort(r.Host)
			if err != nil {
				reqHost = r.Host
				if r.TLS != nil {
					reqPort = "443"
				} else {
					reqPort = "80"
				}
			}
			reqScheme := "http"
			if r.TLS != nil {
				reqScheme = "https"
			}
			// Behind reverse proxy, trust X-Forwarded-Proto
			if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
				reqScheme = proto
			}

			if origin != "" {
				if !originMatchesHostFull(origin, reqHost, reqPort, reqScheme) {
					RespondError(w, http.StatusForbidden, "CSRF_CHECK_FAILED", "Origin mismatch")
					return
				}
			} else if referer != "" {
				if !originMatchesHostFull(referer, reqHost, reqPort, reqScheme) {
					RespondError(w, http.StatusForbidden, "CSRF_CHECK_FAILED", "Referer mismatch")
					return
				}
			} else {
				// No Origin and no Referer — reject state-changing requests
				RespondError(w, http.StatusForbidden, "CSRF_CHECK_FAILED", "Missing Origin and Referer headers")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// originMatchesHostFull checks scheme + host + port for strict CSRF matching.
func originMatchesHostFull(origin, reqHost, reqPort, reqScheme string) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	originHost := u.Hostname()
	originPort := u.Port()
	originScheme := u.Scheme
	if originHost != reqHost {
		return false
	}
	if originPort == "" {
		if originScheme == "https" {
			originPort = "443"
		} else {
			originPort = "80"
		}
	}
	if originPort != reqPort {
		return false
	}
	if originScheme != reqScheme {
		return false
	}
	return true
}

// generateCSRFToken returns 32 random bytes encoded as base64url, which
// the dashboard echoes back in the X-CSRF-Token header on state-changing
// requests. The token is a random opaque value; it is not derived from
// the session, so stealing it via XSS does not grant any privileges on
// its own (the attacker would still need the HttpOnly auth cookie).
func generateCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

const maxBodySize int64 = 1 << 20 // 1MB

// bodySizeMiddleware limits request body size to prevent memory exhaustion.
func bodySizeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
			r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
		}
		next.ServeHTTP(w, r)
	})
}
