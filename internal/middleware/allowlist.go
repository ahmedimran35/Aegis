package middleware

import (
	"context"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// AllowlistRule represents an allow rule.
type AllowlistRule struct {
	ID       int
	RuleType string
	Pattern  string
	network  *net.IPNet
}

// AllowlistChecker enforces default-deny with explicit allow rules.
type AllowlistChecker struct {
	pool    *pgxpool.Pool
	mu      sync.RWMutex
	rules   []AllowlistRule
	enabled bool
	stopCh  chan struct{}
}

// NewAllowlistChecker creates an allowlist checker.
func NewAllowlistChecker(pool *pgxpool.Pool, enabled bool, refreshInterval time.Duration) *AllowlistChecker {
	c := &AllowlistChecker{
		pool:    pool,
		enabled: enabled,
		stopCh:  make(chan struct{}),
	}
	if enabled {
		c.loadRules()
		go c.refreshLoop(refreshInterval)
	}
	return c
}

func (c *AllowlistChecker) refreshLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.loadRules()
		case <-c.stopCh:
			return
		}
	}
}

func (c *AllowlistChecker) loadRules() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rows, err := c.pool.Query(ctx,
		`SELECT id, rule_type, pattern FROM allowlist_rules WHERE enabled = true ORDER BY priority ASC`)
	if err != nil {
		log.Printf("allowlist: load: %v", err)
		return
	}
	defer rows.Close()

	var rules []AllowlistRule
	for rows.Next() {
		var r AllowlistRule
		if err := rows.Scan(&r.ID, &r.RuleType, &r.Pattern); err != nil {
			continue
		}
		if r.RuleType == "cidr" || r.RuleType == "ip" {
			_, network, err := net.ParseCIDR(r.Pattern)
			if err != nil {
				ip := net.ParseIP(r.Pattern)
				if ip != nil {
					if ip.To4() != nil {
						_, network, _ = net.ParseCIDR(r.Pattern + "/32")
					} else {
						_, network, _ = net.ParseCIDR(r.Pattern + "/128")
					}
				}
			}
			r.network = network
		}
		rules = append(rules, r)
	}

	c.mu.Lock()
	c.rules = rules
	c.mu.Unlock()
	log.Printf("allowlist: loaded %d rules", len(rules))
}

// Stop halts the background refresh loop.
func (c *AllowlistChecker) Stop() {
	close(c.stopCh)
}

// IsAllowed checks if a request matches any allow rule.
func (c *AllowlistChecker) IsAllowed(ip net.IP, method, path, host string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for i := range c.rules {
		r := &c.rules[i]
		switch r.RuleType {
		case "ip", "cidr":
			if ip != nil && r.network != nil && r.network.Contains(ip) {
				return true
			}
		case "path":
			if path == r.Pattern {
				return true
			}
		case "path_prefix":
			if path == r.Pattern {
				return true
			}
			if len(path) > len(r.Pattern) && path[:len(r.Pattern)] == r.Pattern && path[len(r.Pattern)] == '/' {
				return true
			}
		case "host":
			if host == r.Pattern {
				return true
			}
		case "method_path":
			mp := method + " " + path
			if mp == r.Pattern {
				return true
			}
		}
	}
	return false
}

// Middleware returns the allowlist middleware handler.
func (c *AllowlistChecker) Middleware(next http.Handler) http.Handler {
	if !c.enabled {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r)
		if c.IsAllowed(ip, r.Method, r.URL.Path, r.Host) {
			next.ServeHTTP(w, r)
			return
		}

		log.Printf("allowlist: denied %s %s from %s", r.Method, sanitizeLog(r.URL.Path), ip)
		writeBlockError(w, "ALLOWLIST_DENIED", "request not in allowlist (default-deny mode)")
	})
}
