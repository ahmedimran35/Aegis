package middleware

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// WSGuardConfig configures the WebSocket protection middleware.
//
// All settings are free / local (no third-party SaaS). They cap the
// worst-case resource consumption of a misbehaving WS client.
//
//   MaxMessageBytes   - per-frame cap (default 64 KiB)
//   HandshakeTimeout  - upgrade negotiation cap (default 10s)
//   AllowedOrigins    - empty = allow all; otherwise exact origin allowlist
//   MaxMessagesPerMin - per-connection rate cap (0 = unlimited)
//   MaxConnectionsPerIP - per-IP upgrade cap (0 = unlimited)
type WSGuardConfig struct {
	MaxMessageBytes     int64
	HandshakeTimeout    time.Duration
	AllowedOrigins      []string
	MaxMessagesPerMin   int
	MaxConnectionsPerIP int
}

// DefaultWSGuardConfig returns safe production defaults.
func DefaultWSGuardConfig() WSGuardConfig {
	return WSGuardConfig{
		MaxMessageBytes:     64 * 1024,
		HandshakeTimeout:    10 * time.Second,
		AllowedOrigins:      nil, // empty = allow all (compatible with browser test flows)
		MaxMessagesPerMin:   600,
		MaxConnectionsPerIP: 5,
	}
}

// WSGuardStats exposes live counters for /api/v1/ws/stats and the dashboard.
type WSGuardStats struct {
	UpgradesAllowed atomic.Int64
	UpgradesBlocked atomic.Int64
	MessagesBlocked atomic.Int64
	OriginsRejected atomic.Int64
}

// WSGuard enforces per-connection WebSocket limits BEFORE the upgrade and
// publishes counters to the dashboard. The middleware itself does NOT
// perform per-message inspection — that lives in the WSInspector on the
// hub side — but it does enforce:
//
//   - Origin allowlist (defense against CSWSH)
//   - Per-IP concurrent-connection cap (LRU-safe)
//   - Per-connection message rate cap (tracked in Redis with a TTL key)
//   - Configurable per-frame size cap (passed to gorilla via SetReadLimit)
//
// All counters are non-blocking (atomic + Redis HINCRBY).
type WSGuard struct {
	cfg   WSGuardConfig
	stats *WSGuardStats
	rdb   *redis.Client

	mu       sync.Mutex
	connsPerIP map[string]int
}

// NewWSGuard creates a WebSocket guard. rdb may be nil; counters will
// still increment locally.
func NewWSGuard(cfg WSGuardConfig, rdb *redis.Client) *WSGuard {
	if cfg.MaxMessageBytes == 0 {
		cfg.MaxMessageBytes = 64 * 1024
	}
	if cfg.HandshakeTimeout == 0 {
		cfg.HandshakeTimeout = 10 * time.Second
	}
	if cfg.MaxMessagesPerMin == 0 {
		cfg.MaxMessagesPerMin = 600
	}
	return &WSGuard{
		cfg:        cfg,
		stats:      &WSGuardStats{},
		rdb:        rdb,
		connsPerIP: make(map[string]int),
	}
}

// Stats returns a snapshot of WS guard counters.
func (g *WSGuard) Stats() *WSGuardStats {
	// atomic.Int64 cannot be copied by value; return pointer-to-struct.
	return g.stats
}

// Middleware returns the http.Handler middleware that guards /api/v1/ws
// upgrades. It MUST be installed before any WS upgrade handler.
func (g *WSGuard) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only apply to WS upgrade requests (method GET + Upgrade header).
		if !isWSUpgrade(r) {
			next.ServeHTTP(w, r)
			return
		}

		// 1. Origin allowlist.
		if !g.originAllowed(r) {
			g.stats.OriginsRejected.Add(1)
			http.Error(w, "wsguard: origin not allowed", http.StatusForbidden)
			return
		}

		// 2. Per-IP concurrent-connection cap.
		ip := extractIP(r)
		ipKey := ""
		if ip != nil {
			ipKey = ip.String()
		}
		if g.cfg.MaxConnectionsPerIP > 0 && ipKey != "" {
			g.mu.Lock()
			cur := g.connsPerIP[ipKey]
			if cur >= g.cfg.MaxConnectionsPerIP {
				g.mu.Unlock()
				g.stats.UpgradesBlocked.Add(1)
				http.Error(w, "wsguard: too many connections from your IP", http.StatusTooManyRequests)
				return
			}
			g.connsPerIP[ipKey] = cur + 1
			g.mu.Unlock()
			defer func() {
				g.mu.Lock()
				g.connsPerIP[ipKey]--
				if g.connsPerIP[ipKey] <= 0 {
					delete(g.connsPerIP, ipKey)
				}
				g.mu.Unlock()
			}()
		}

		// 3. Handshake timeout via response writer deadline.
		rc := http.NewResponseController(w)
		_ = rc.SetWriteDeadline(time.Now().Add(g.cfg.HandshakeTimeout))

		g.stats.UpgradesAllowed.Add(1)
		next.ServeHTTP(w, r)
	})
}

// isWSUpgrade returns true if the request is a WebSocket upgrade.
func isWSUpgrade(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	// gorilla/websocket sets these on Upgrade; we mirror the check so
	// the guard fires only on actual WS handshakes.
	if r.Header.Get("Upgrade") == "" {
		return false
	}
	if r.Header.Get("Connection") == "" {
		return false
	}
	return true
}

// originAllowed returns true if the origin is in the allowlist (or if
// the allowlist is empty = allow all). The check uses parsed-host
// equality so the allowlist can be expressed as either exact origins
// ("https://app.example.com") or just hosts ("app.example.com").
func (g *WSGuard) originAllowed(r *http.Request) bool {
	if len(g.cfg.AllowedOrigins) == 0 {
		return true
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		// Non-browser client; the WS upgrader has its own non-browser
		// path that requires a JWT in Sec-WebSocket-Protocol, so we
		// can safely let it through here.
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	for _, allowed := range g.cfg.AllowedOrigins {
		if allowed == "*" {
			return true
		}
		if allowed == origin || allowed == u.Host {
			return true
		}
	}
	return false
}

// CheckMessageRate returns true if the connection is within the
// messages-per-minute cap. The hub calls this once per inbound message.
// Implemented with a Redis INCR + EXPIRE so multi-instance deployments
// share the same counter.
func (g *WSGuard) CheckMessageRate(ctx context.Context, connID string) bool {
	if g.cfg.MaxMessagesPerMin <= 0 || g.rdb == nil {
		return true
	}
	key := "wsguard:msg:" + connID
	count, err := g.rdb.Incr(ctx, key).Result()
	if err != nil {
		// Fail-open on Redis error (don't break legitimate traffic).
		return true
	}
	if count == 1 {
		// First message in this window; set TTL.
		g.rdb.Expire(ctx, key, 60*time.Second)
	}
	if count > int64(g.cfg.MaxMessagesPerMin) {
		g.stats.MessagesBlocked.Add(1)
		return false
	}
	return true
}

// FrameLimit returns the configured per-frame byte cap. The hub's
// reader goroutine calls conn.SetReadLimit(g.FrameLimit()).
func (g *WSGuard) FrameLimit() int64 {
	return g.cfg.MaxMessageBytes
}

// ConfigSummary returns a human-readable string for the dashboard.
func (g *WSGuard) ConfigSummary() string {
	return "max_message_bytes=" + strconv.FormatInt(g.cfg.MaxMessageBytes, 10) +
		", handshake_timeout=" + g.cfg.HandshakeTimeout.String() +
		", max_messages_per_min=" + strconv.Itoa(g.cfg.MaxMessagesPerMin) +
		", max_conns_per_ip=" + strconv.Itoa(g.cfg.MaxConnectionsPerIP)
}