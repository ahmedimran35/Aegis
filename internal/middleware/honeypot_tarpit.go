package middleware

import (
	"container/list"
	"context"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// HoneypotTarpit extends HoneypotTrap with two new behaviors:
//
//   1. SLOW-DRIP RESPONSE — instead of writing the full fake response
//      immediately, write it one byte every 10s.
//   2. AUTO-IP-BLACKLIST — on a confirmed hit, block the source IP for
//      blacklistTTL (default 1h).
type HoneypotTarpit struct {
	pool          *pgxpool.Pool
	pathPrefixes  []string
	enabled       bool
	dripByteEvery time.Duration
	dripMaxBytes  int
	blacklistTTL  time.Duration

	// F35: bounded worker pool for background recordAndBlock tasks. A
	// botnet hitting the same decoy can otherwise spawn an unbounded
	// number of goroutines, each running a Postgres insert.
	recordWorkers chan struct{}

	// H-6: blacklist is bounded by maxBlacklist (LRU via container/list).
	// When the map reaches maxBlacklist entries, the oldest insertion is
	// evicted to keep memory bounded under sustained attacks from
	// thousands of unique IPs.
	mu          sync.RWMutex
	blacklist   map[string]*list.Element
	blacklistLL *list.List
	maxBlacklist int

	// H-6: periodic cleanup goroutine.
	cleanupStop chan struct{}
	cleanupDone chan struct{}
}

// blacklistEntry is the value stored in the LRU list.
type blacklistEntry struct {
	ip  string
	exp time.Time
}

// H-6: default cap on the LRU blacklist.
const defaultHoneypotMaxBlacklist = 10000

// NewHoneypotTarpit returns a tarpit honeypot with defaults: 1 byte every 10s,
// max 600 bytes dripped (4 hours), blacklist TTL 1h.
func NewHoneypotTarpit(pool *pgxpool.Pool, paths []string, enabled bool) *HoneypotTarpit {
	h := &HoneypotTarpit{
		pool:          pool,
		pathPrefixes:  paths,
		enabled:       enabled,
		dripByteEvery: 10 * time.Second,
		dripMaxBytes:  600,
		blacklistTTL:  1 * time.Hour,
		blacklist:     make(map[string]*list.Element),
		blacklistLL:   list.New(),
		maxBlacklist:  defaultHoneypotMaxBlacklist,
		recordWorkers: make(chan struct{}, 100), // F35: bounded worker pool
		cleanupStop:   make(chan struct{}),
		cleanupDone:   make(chan struct{}),
	}
	// H-6: background cleanup every 5 minutes evicts expired entries.
	go h.cleanupLoop()
	return h
}

// IsBlacklisted returns true when the IP is currently blocked.
func (h *HoneypotTarpit) IsBlacklisted(ip string) bool {
	h.mu.RLock()
	el, ok := h.blacklist[ip]
	h.mu.RUnlock()
	if !ok {
		return false
	}
	exp := el.Value.(*blacklistEntry).exp
	if time.Now().After(exp) {
		h.mu.Lock()
		h.blacklistLL.Remove(el)
		delete(h.blacklist, ip)
		h.mu.Unlock()
		return false
	}
	return true
}

// IsHoneypot returns true when the request path matches a configured decoy.
func (h *HoneypotTarpit) IsHoneypot(path string) bool {
	if !h.enabled {
		return false
	}
	for _, prefix := range h.pathPrefixes {
		if len(path) >= len(prefix) && path[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

// TrapHandler returns the HTTP handler that traps and tarpits hits. Replaces
// the existing Trap on HoneypotTrap when wired through NewHoneypotTarpit.
//
// F35: the background recordAndBlock is wrapped in the bounded worker
// pool. If the pool is saturated (a sustained attack has filled it) we
// drop the recording task rather than spawning an unbounded goroutine.
func (h *HoneypotTarpit) TrapHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		h.drip(w, r)
		select {
		case h.recordWorkers <- struct{}{}:
			go func() {
				defer func() { <-h.recordWorkers }()
				h.recordAndBlock(ip, r)
			}()
		default:
			log.Printf("honeypot: worker pool saturated, dropping record for %s", sanitizeLog(ip))
		}
	})
}

// clientIP extracts the source IP used to key the honeypot blacklist.
//
// P-FIX: previously this function trusted X-Forwarded-For from any
// connection, allowing an attacker to bypass the blacklist by rotating
// the XFF header on each request (the blacklist entry was keyed on the
// first XFF hop, not the actual RemoteAddr). The blacklist is now keyed
// on RemoteAddr unless the connection came from a configured trusted
// proxy, in which case the first non-trusted XFF hop is used.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	remoteIP := net.ParseIP(host)
	if remoteIP == nil {
		return host
	}
	if !isTrustedProxy(remoteIP) {
		return host
	}
	// Trusted proxy: walk XFF from right (closest to us) until we hit a
	// non-trusted IP; that's the real client.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			ipStr := strings.TrimSpace(parts[i])
			ip := net.ParseIP(ipStr)
			if ip == nil {
				continue
			}
			if !isTrustedProxy(ip) {
				return ipStr
			}
		}
	}
	return host
}

// drip writes the tarpit slow-drip response. Sends 1 byte every 10s until
// either dripMaxBytes reached or the client closes the connection. Flusher
// must be implemented by the ResponseWriter or this becomes a no-op (the
// normal Go http.ResponseWriter DOES support Flusher).
//
// F36/F42: select on r.Context().Done() so we exit promptly when the
// client disconnects, instead of holding a goroutine for the full
// dripByteEvery interval.
func (h *HoneypotTarpit) drip(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher, ok := w.(http.Flusher)
	if !ok {
		// Without a flusher we cannot drip — fall back to immediate full
		// write of benign body so the attacker at least sees *something*.
		_, _ = w.Write([]byte("Loading..."))
		return
	}
	for i := 0; i < h.dripMaxBytes; i++ {
		_, err := w.Write([]byte{'.'})
		if err != nil {
			return
		}
		flusher.Flush()
		t := time.NewTimer(h.dripByteEvery)
		select {
		case <-t.C:
		case <-r.Context().Done():
			t.Stop()
			return
		}
	}
}

func (h *HoneypotTarpit) recordAndBlock(ip string, r *http.Request) {
	exp := time.Now().Add(h.blacklistTTL)
	ttl := h.blacklistTTL
	h.mu.Lock()
	if el, ok := h.blacklist[ip]; ok {
		el.Value.(*blacklistEntry).exp = exp
		h.blacklistLL.MoveToFront(el)
	} else {
		el := h.blacklistLL.PushFront(&blacklistEntry{ip: ip, exp: exp})
		h.blacklist[ip] = el
		// H-6: evict oldest entries beyond the cap.
		for h.blacklistLL.Len() > h.maxBlacklist {
			oldest := h.blacklistLL.Back()
			if oldest == nil {
				break
			}
			h.blacklistLL.Remove(oldest)
			delete(h.blacklist, oldest.Value.(*blacklistEntry).ip)
		}
	}
	h.mu.Unlock()

	if h.pool != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := h.pool.Exec(ctx, `INSERT INTO honeypot_hits (client_ip, method, path, ts) VALUES ($1, $2, $3, NOW())`,
			ip, r.Method, r.URL.Path)
		if err != nil {
			log.Printf("honeypot: insert error: %v", err)
		}
	}
	log.Printf("honeypot: blocked ip=%s for %s after hit %s %s", ip, ttl, r.Method, r.URL.Path)
}

// CleanupBlacklist evicts expired blacklist entries. Run periodically.
func (h *HoneypotTarpit) CleanupBlacklist() int {
	now := time.Now()
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for el := h.blacklistLL.Front(); el != nil; {
		next := el.Next()
		entry := el.Value.(*blacklistEntry)
		if now.After(entry.exp) {
			h.blacklistLL.Remove(el)
			delete(h.blacklist, entry.ip)
			n++
		}
		el = next
	}
	return n
}

// H-6: cleanupLoop runs CleanupBlacklist every 5 minutes and is stopped
// via Stop().
func (h *HoneypotTarpit) cleanupLoop() {
	defer close(h.cleanupDone)
	defer func() {
		if r := recover(); r != nil {
			log.Printf("honeypot: cleanup loop panic recovered: %v", r)
		}
	}()
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-h.cleanupStop:
			return
		case <-ticker.C:
			h.CleanupBlacklist()
		}
	}
}

// Stop halts the cleanup goroutine. Safe to call multiple times.
func (h *HoneypotTarpit) Stop() {
	select {
	case <-h.cleanupStop:
		return
	default:
		close(h.cleanupStop)
	}
	<-h.cleanupDone
}

// Stats returns a snapshot.
func (h *HoneypotTarpit) Stats() map[string]interface{} {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return map[string]interface{}{
		"enabled":     h.enabled,
		"blacklisted": h.blacklistLL.Len(),
		"drip_every":  h.dripByteEvery.String(),
		"max_bytes":   h.dripMaxBytes,
	}
}
