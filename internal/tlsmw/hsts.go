// Package tlsmw provides TLS-related HTTP middleware: HSTS, MaxBytesReader,
// and HTTP request smuggling detection. These run on every request regardless
// of whether TLS termination is in front of Aegis or behind it.
package tlsmw

import (
	"net/http"
	"strconv"
	"strings"
)

// HSTSHeader returns middleware that sets Strict-Transport-Security on every
// response. Recommended max-age is 2 years (63072000 seconds) with
// includeSubDomains and preload directives for HSTS preload list submission.
//
// The header is set on HTTP responses too. This is harmless: browsers ignore
// HSTS over HTTP but still cache the policy for the host once seen over HTTPS.
func HSTSHeader(maxAge int, includeSubdomains, preload bool) func(http.Handler) http.Handler {
	if maxAge == 0 {
		maxAge = 63072000 // 2 years
	}
	parts := []string{"max-age=" + strconv.Itoa(maxAge)}
	if includeSubdomains {
		parts = append(parts, "includeSubDomains")
	}
	if preload {
		parts = append(parts, "preload")
	}
	value := strings.Join(parts, "; ")

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Strict-Transport-Security", value)
			next.ServeHTTP(w, r)
		})
	}
}

// ModernCipherSuites returns a curated list of TLS 1.2 cipher suites ordered
// by preference. All are ECDHE-based (forward secrecy) and use AEAD (AES-GCM
// or ChaCha20-Poly1305). TLS 1.3 cipher suites are not configurable via this
// list; Go negotiates them automatically and the chosen suites are always
// secure.
//
// Reference: Mozilla "Modern" SSL configuration.
func ModernCipherSuites() []uint16 {
	return []uint16{
		// TLS 1.3 cipher suites (constants from crypto/tls, included for clarity;
		// Go selects these automatically and CipherSuites is ignored for TLS 1.3).
		// TLS_AES_256_GCM_SHA384 = 0x1302
		// TLS_CHACHA20_POLY1305_SHA256 = 0x1303
		// TLS_AES_128_GCM_SHA256 = 0x1301

		// TLS 1.2 ECDHE+AEAD suites (forward secrecy).
		tlsECDHEECDSAWithAES256GCMSHA384, // 0xC02C
		tlsECDHERSAWithAES256GCMSHA384,   // 0xC030
		tlsECDHEECDSAWithCHACHA20POLY1305, // 0xCCA9
		tlsECDHERSAWithCHACHA20POLY1305,  // 0xCCA8
		tlsECDHEECDSAWithAES128GCMSHA256, // 0xC02B
		tlsECDHERSAWithAES128GCMSHA256,   // 0xC02F
	}
}

// TLS 1.2 cipher suite constants (avoid pulling crypto/tls into a file that
// might be imported by clients that don't need it).
const (
	tlsECDHEECDSAWithAES256GCMSHA384  uint16 = 0xC02C
	tlsECDHERSAWithAES256GCMSHA384    uint16 = 0xC030
	tlsECDHEECDSAWithCHACHA20POLY1305 uint16 = 0xCCA9
	tlsECDHERSAWithCHACHA20POLY1305   uint16 = 0xCCA8
	tlsECDHEECDSAWithAES128GCMSHA256  uint16 = 0xC02B
	tlsECDHERSAWithAES128GCMSHA256    uint16 = 0xC02F
)

// HTTPSRedirect returns middleware that 301-redirects HTTP requests to HTTPS.
// targetScheme is "https"; targetHost can be empty to use r.Host.
//
// This middleware should only run on the plaintext HTTP listener, not on the
// HTTPS listener (otherwise it loops).
func HTTPSRedirect(targetHost string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Allow ACME challenges through (Let's Encrypt http-01).
			if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
				next.ServeHTTP(w, r)
				return
			}
			host := targetHost
			if host == "" {
				host = r.Host
			}
			dest := "https://" + host + r.URL.RequestURI()
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
			http.Redirect(w, r, dest, http.StatusMovedPermanently)
		})
	}
}