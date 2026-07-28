// Package middleware: AdaptiveDDoS middleware wrapper.
//
// Wraps the library-style AdaptiveDDoS.Evaluate() into a chi-style
// Middleware so it can be inserted into the pipeline. Per-request it
// calls Evaluate with the connection IP, request URI, user-agent, and
// selected headers; if Evaluate returns flagged=true, the request is
// blocked with HTTP 429.
//
// Also runs a periodic CleanupStale goroutine to bound the memory
// footprint of the per-IP entropy map (default 10-minute threshold, runs
// every minute).
package middleware

import (
	"container/list"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// NewAdaptiveDDoSMiddleware returns a middleware that runs the
// AdaptiveDDoS heuristic per request. The instance keeps its own
// cleanup goroutine started on first invocation.
func NewAdaptiveDDoSMiddleware(db interface{}) func(http.Handler) http.Handler {
	a := &AdaptiveDDoS{
		seen:       make(map[string]*list.Element),
		seenLL:     list.New(),
		maxSeen:    defaultAdaptiveMaxSeen,
		stopCh:     make(chan struct{}),
		cleanupDone: make(chan struct{}),
	}
	a.startCleanup(10 * time.Minute, 1 * time.Minute)
	_ = db // unused; reserved for future Redis-backed state
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				host = r.RemoteAddr
			}
			ua := r.UserAgent()
			ja3 := r.Header.Get("X-JA3-Fingerprint")
			headers := map[string][]string{}
			for _, h := range []string{"Accept", "Accept-Language", "Accept-Encoding", "Referer"} {
				if v := r.Header.Get(h); v != "" {
					headers[h] = []string{v}
				}
			}
			flagged, reasons := a.Evaluate(host, r.URL.Path, ua, ja3, headers)
			if flagged {
				log.Printf("adaptive-ddos: blocking %s reasons=%v", host, reasons)
				writeBlockError(w, "ADAPTIVE_DDOS", "request flagged by adaptive DDoS heuristic: "+joinReasons(reasons))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// startCleanup launches a periodic goroutine that calls CleanupStale
// every interval. Safe to call multiple times via sync.Once.
func (a *AdaptiveDDoS) startCleanup(olderThan, interval time.Duration) {
	a.cleanupOnce.Do(func() {
		go func() {
			t := time.NewTicker(interval)
			defer t.Stop()
			for range t.C {
				n := a.CleanupStale(olderThan)
				if n > 0 {
					log.Printf("adaptive-ddos: cleanup removed %d stale entries", n)
				}
			}
		}()
	})
}

func joinReasons(rs []string) string {
	return strings.Join(rs, ", ")
}