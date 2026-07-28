package middleware

import (
	"context"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// trustedProxies holds CIDR ranges of trusted reverse proxies.
// When a request comes from one of these, X-Real-IP is trusted.
//
// M-9: guarded by trustedProxiesMu. The slice is only mutated during
// InitTrustedProxies (startup), but read on every request, and a race
// detector run during a graceful restart can otherwise trip.
var (
	trustedProxiesMu sync.RWMutex
	trustedProxies   []*net.IPNet
)

// defaultTrustedProxies are always trusted (localhost only).
// Docker bridge (172.16.0.0/12) and RFC1918 (10.0.0.0/8) are NOT trusted by default.
// Configure AEGIS_TRUSTED_PROXIES env var for production deployments behind proxies.
var defaultTrustedProxies = []string{
	"127.0.0.0/8",
	"::1/128",
}

// InitTrustedProxies configures which proxy IPs are trusted for X-Real-IP.
// Call once at startup. If extraCIDRs is empty, defaults are used.
func InitTrustedProxies(extraCIDRs string) {
	cidrs := defaultTrustedProxies
	if extraCIDRs != "" {
		cidrs = append(cidrs, strings.Split(extraCIDRs, ",")...)
	}
	parsed := []*net.IPNet{}
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		_, network, err := net.ParseCIDR(c)
		if err != nil {
			// Try as single IP
			ip := net.ParseIP(c)
			if ip != nil {
				if ip.To4() != nil {
					_, network, _ = safeParseCIDR(c + "/32")
				} else {
					_, network, _ = safeParseCIDR(c + "/128")
				}
			}
			if network == nil {
				log.Printf("trusted-proxies: invalid CIDR %q, skipping", c)
				continue
			}
		}
		parsed = append(parsed, network)
	}

	// Also trust env-configured proxies
	if env := os.Getenv("AEGIS_TRUSTED_PROXIES"); env != "" && extraCIDRs == "" {
		for _, c := range strings.Split(env, ",") {
			c = strings.TrimSpace(c)
			if c == "" {
				continue
			}
			_, network, err := net.ParseCIDR(c)
			if err != nil {
				ip := net.ParseIP(c)
				if ip != nil {
					if ip.To4() != nil {
						_, network, _ = safeParseCIDR(c + "/32")
					} else {
						_, network, _ = safeParseCIDR(c + "/128")
					}
				}
				if network == nil {
					continue
				}
			}
			parsed = append(parsed, network)
		}
	}

	// Initialize defaults if nothing was configured
	if len(parsed) == 0 {
		for _, c := range defaultTrustedProxies {
			_, network, _ := safeParseCIDR(c)
			parsed = append(parsed, network)
		}
	}

	trustedProxiesMu.Lock()
	trustedProxies = parsed
	trustedProxiesMu.Unlock()
}

// isTrustedProxy checks if an IP is in the trusted proxy list.
func isTrustedProxy(ip net.IP) bool {
	trustedProxiesMu.RLock()
	defer trustedProxiesMu.RUnlock()
	for _, network := range trustedProxies {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// safeParseCIDR wraps net.ParseCIDR in a deferred recover() to handle
// the documented case where IPv6 addresses with a Zone identifier
// (e.g. "fe80::1%eth0") cause ParseCIDR to panic. M-23.
func safeParseCIDR(s string) (net.IP, *net.IPNet, error) {
	defer func() {
		_ = recover()
	}()
	return net.ParseCIDR(s)
}

// IsTrustedProxyReq returns true when the request's RemoteAddr belongs to
// a configured trusted reverse proxy. Other code (cookie Secure flag,
// X-Forwarded-For honor, SCIM middleware) uses this to decide whether
// client-supplied connection metadata can be trusted. Returns false when
// the remote address cannot be parsed or the proxy list is empty.
func IsTrustedProxyReq(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return isTrustedProxy(ip)
}

// BlockedIP holds a CIDR network and its metadata.
type BlockedIP struct {
	Network   *net.IPNet
	Reason    string
	Source    string
	ExpiresAt *time.Time
}

// IPChecker loads blocked IPs from Postgres and checks requests.
type IPChecker struct {
	pool    *pgxpool.Pool
	mu      sync.RWMutex
	blocked []BlockedIP
	stopCh  chan struct{}
}

// NewIPChecker creates an IPChecker that refreshes blocked IPs every interval.
func NewIPChecker(pool *pgxpool.Pool, refreshInterval time.Duration) *IPChecker {
	c := &IPChecker{
		pool:   pool,
		stopCh: make(chan struct{}),
	}
	c.loadBlockedIPs()
	go c.refreshLoop(refreshInterval)
	return c
}

func (c *IPChecker) refreshLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.loadBlockedIPs()
		case <-c.stopCh:
			return
		}
	}
}

func (c *IPChecker) loadBlockedIPs() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rows, err := c.pool.Query(ctx,
		`SELECT ip_cidr, reason, source, expires_at
		 FROM blocked_ips
		 WHERE expires_at IS NULL OR expires_at > NOW()`)
	if err != nil {
		log.Printf("ipcheck: load blocked IPs: %v", err)
		return
	}
	defer rows.Close()

	var blocked []BlockedIP
	for rows.Next() {
		var ipCIDR string
		var reason, source string
		var expiresAt *time.Time
		if err := rows.Scan(&ipCIDR, &reason, &source, &expiresAt); err != nil {
			log.Printf("ipcheck: scan row: %v", err)
			continue
		}
		_, network, err := safeParseCIDR(ipCIDR)
		if err != nil {
			// Try parsing as single IP
			ip := net.ParseIP(ipCIDR)
			if ip == nil {
				log.Printf("ipcheck: parse CIDR %q: %v", ipCIDR, err)
				continue
			}
			// Convert single IP to /32 or /128
			if ip.To4() != nil {
				_, network, _ = safeParseCIDR(ipCIDR + "/32")
			} else {
				_, network, _ = safeParseCIDR(ipCIDR + "/128")
			}
		}
		blocked = append(blocked, BlockedIP{
			Network:   network,
			Reason:    reason,
			Source:    source,
			ExpiresAt: expiresAt,
		})
	}

	c.mu.Lock()
	c.blocked = blocked
	c.mu.Unlock()
	log.Printf("ipcheck: loaded %d blocked IPs", len(blocked))
}

// Stop halts the background refresh loop.
func (c *IPChecker) Stop() {
	close(c.stopCh)
}

// IsBlocked checks if the given IP is in the blocked list.
func (c *IPChecker) IsBlocked(ip net.IP) *BlockedIP {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for i := range c.blocked {
		if c.blocked[i].Network.Contains(ip) {
			return &c.blocked[i]
		}
	}
	return nil
}

// Middleware returns the IP check middleware handler.
func (c *IPChecker) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r)
		if ip == nil {
			writeError(w, http.StatusBadRequest, "INVALID_IP", "could not parse client IP")
			return
		}

		if blocked := c.IsBlocked(ip); blocked != nil {
			// Sanitize IP to avoid log injection (remove control chars)
			ipStr := sanitizeLog(ip.String())
			log.Printf("ipcheck: blocked %s", ipStr)
			writeBlockError(w, "IP_BLOCKED", "your IP is blocked")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ExtractClientIP returns the real client IP. When the request comes from a
// trusted proxy (e.g., nginx), X-Real-IP is used. Otherwise RemoteAddr.
func ExtractClientIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	remoteIP := net.ParseIP(host)
	if remoteIP == nil {
		return nil
	}

	// If request is from a trusted proxy, read X-Real-IP
	if isTrustedProxy(remoteIP) {
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			if ip := net.ParseIP(xri); ip != nil {
				return ip
			}
		}
	}

	return remoteIP
}

// extractIP gets the real client IP, trusting X-Real-IP from known proxies.
func extractIP(r *http.Request) net.IP {
	return ExtractClientIP(r)
}
