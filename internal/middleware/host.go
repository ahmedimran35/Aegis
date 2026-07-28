// hostHeaderValidator enforces that r.Host matches the configured server
// address. SECURITY: prevents Host header injection attacks where an
// attacker sends "Host: evil.com" and tricks cache-poisoning or
// password-reset flows. Non-functional change: rejects requests that
// would have been served anyway — no legitimate client ever uses a
// Host header that doesn't match the server's actual address.
package middleware

import (
	"net"
	"net/http"
	"strings"
	"sync"
)

type HostValidator struct {
	mu     sync.RWMutex
	allow  map[string]bool
	strict bool
}

// NewHostValidator initializes the validator. allowedHosts is the set
// of Host header values the server will accept (typically ["127.0.0.1:8080",
// "localhost:8080", "aegis.local"]).
func NewHostValidator(allowedHosts []string) *HostValidator {
	allow := make(map[string]bool, len(allowedHosts))
	for _, h := range allowedHosts {
		allow[strings.ToLower(h)] = true
	}
	return &HostValidator{allow: allow, strict: len(allowedHosts) > 0}
}

// Middleware enforces the Host header. If strict=false the validator
// passes through anything (dev mode); if strict=true it rejects.
func (h *HostValidator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !h.strict {
			next.ServeHTTP(w, r)
			return
		}
		host := r.Host
		// strip port
		if strings.Contains(host, ":") {
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
		}
		host = strings.ToLower(host)
		h.mu.RLock()
		ok := h.allow[host] || h.allow[strings.ToLower(r.Host)]
		h.mu.RUnlock()
		if !ok {
			http.Error(w, "invalid Host header", http.StatusBadRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}
