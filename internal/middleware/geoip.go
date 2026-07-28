package middleware

import (
	"context"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/oschwald/maxminddb-golang"
)

// GeoIPRule represents a country block/allow rule.
type GeoIPRule struct {
	CountryCode string
	Action      string
}

// GeoIPChecker provides country-based request filtering.
type GeoIPChecker struct {
	pool         *pgxpool.Pool
	mu           sync.RWMutex
	rules        map[string]GeoIPRule // country_code -> rule
	db           *maxminddb.Reader
	enabled      bool
	stopCh       chan struct{}
}

// NewGeoIPChecker creates a GeoIP checker.
func NewGeoIPChecker(pool *pgxpool.Pool, dbPath string, enabled bool, refreshInterval time.Duration) *GeoIPChecker {
	c := &GeoIPChecker{
		pool:    pool,
		rules:   make(map[string]GeoIPRule),
		enabled: enabled,
		stopCh:  make(chan struct{}),
	}

	if !enabled {
		return c
	}

	// Load MaxMind DB
	db, err := maxminddb.Open(dbPath)
	if err != nil {
		log.Printf("geoip: cannot open database %s: %v (geoip disabled)", dbPath, err)
		c.enabled = false
		return c
	}
	c.db = db
	log.Printf("geoip: loaded database from %s", dbPath)

	c.loadRules()
	go c.refreshLoop(refreshInterval)
	return c
}

func (c *GeoIPChecker) refreshLoop(interval time.Duration) {
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

func (c *GeoIPChecker) loadRules() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rows, err := c.pool.Query(ctx,
		`SELECT country_code, action FROM geoip_rules WHERE enabled = true`)
	if err != nil {
		log.Printf("geoip: load rules: %v", err)
		return
	}
	defer rows.Close()

	rules := make(map[string]GeoIPRule)
	for rows.Next() {
		var r GeoIPRule
		if err := rows.Scan(&r.CountryCode, &r.Action); err != nil {
			continue
		}
		rules[r.CountryCode] = r
	}

	c.mu.Lock()
	c.rules = rules
	c.mu.Unlock()
	log.Printf("geoip: loaded %d country rules", len(rules))
}

// LookupCountry returns the country code for an IP.
func (c *GeoIPChecker) LookupCountry(ip net.IP) string {
	if c.db == nil {
		return ""
	}

	var record struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}

	if err := c.db.Lookup(ip, &record); err != nil {
		return ""
	}
	return record.Country.ISOCode
}

// IsBlocked checks if a country is blocked.
func (c *GeoIPChecker) IsBlocked(countryCode string) *GeoIPRule {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if r, ok := c.rules[countryCode]; ok && r.Action == "block" {
		return &r
	}
	return nil
}

// Stop halts the background refresh loop.
func (c *GeoIPChecker) Stop() {
	close(c.stopCh)
	if c.db != nil {
		c.db.Close()
	}
}

// Middleware returns the GeoIP blocking middleware.
func (c *GeoIPChecker) Middleware(next http.Handler) http.Handler {
	if !c.enabled {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r)
		if ip == nil {
			next.ServeHTTP(w, r)
			return
		}

		country := c.LookupCountry(ip)
		if country == "" {
			next.ServeHTTP(w, r)
			return
		}

		if rule := c.IsBlocked(country); rule != nil {
			log.Printf("geoip: blocked %s (%s) from %s", country, ip, sanitizeLog(r.URL.Path))
			writeBlockError(w, "GEOIP_BLOCKED", "access denied from your region")
			return
		}

		// Store country in context
		ctx := context.WithValue(r.Context(), countryKey, country)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

const countryKey ctxKey = "country_code"

// CountryFromContext extracts country code from context.
func CountryFromContext(ctx context.Context) string {
	v, _ := ctx.Value(countryKey).(string)
	return v
}
