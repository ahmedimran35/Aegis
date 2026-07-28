package middleware

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/user/waf/internal/threatfeed"
)

// ThreatFeedConfig configures the free community blocklist middleware.
type ThreatFeedConfig struct {
	Enabled        bool
	AutoBlock      bool   // if true, block on hit; if false, only flag in threat score
	RequestTimeout time.Duration
}

// ThreatFeedStats holds counters for /api/v1/threatfeed/stats.
type ThreatFeedStats struct {
	Checks atomic.Int64
	Blocks atomic.Int64
	Hits   atomic.Int64
}

// ThreatFeedMiddleware checks the client IP against community-curated
// free blocklists (CrowdSec, FireHOL) cached in Redis. Replaces paid
// reputation feeds for most operators — no API key required.
func ThreatFeedMiddleware(puller *threatfeed.Puller, cfg ThreatFeedConfig, stats *ThreatFeedStats) Middleware {
	if !cfg.Enabled || puller == nil {
		return func(next http.Handler) http.Handler { return next }
	}
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = 500 * time.Millisecond
	}
	if stats == nil {
		stats = &ThreatFeedStats{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := extractIP(r)
			if ip == nil || isPrivateIPRep(ip) {
				next.ServeHTTP(w, r)
				return
			}
			stats.Checks.Add(1)
			ctx, cancel := context.WithTimeout(r.Context(), cfg.RequestTimeout)
			defer cancel()
			blocked, feed := puller.IsBlocked(ctx, ip.String())
			if blocked {
				stats.Hits.Add(1)
				// Always flag in threat score
				if m := MetricsFromContext(r.Context()); m != nil {
					if 1.0 > m.ThreatScore {
						m.ThreatScore = 1.0
					}
				}
				log.Printf("threatfeed: hit %s in feed %s", sanitizeLog(ip.String()), feed)
				if cfg.AutoBlock {
					stats.Blocks.Add(1)
					writeBlockError(w, "THREATFEED_BLOCKED",
						fmt.Sprintf("IP is in community blocklist %s", feed))
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// re-declare so we don't need an extra import in this file
var _ = net.IPv4len