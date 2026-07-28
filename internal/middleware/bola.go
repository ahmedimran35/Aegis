package middleware

import (
	"context"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/user/waf/internal/auth"
)

// BOLAConfig configures BOLA/IDOR detection.
type BOLAConfig struct {
	Enabled          bool
	AnomalyThreshold float64
}

// DefaultBOLAConfig returns safe production defaults.
func DefaultBOLAConfig() BOLAConfig {
	return BOLAConfig{
		Enabled:          true,
		AnomalyThreshold: 0.3,
	}
}

// BOLADetector detects broken object-level authorization.
type BOLADetector struct {
	enabled int32
	cfg     BOLAConfig
	stats   *bolaStats
	rdb     *redis.Client
}

type bolaStats struct {
	mu              sync.Mutex
	ChecksPerformed int64
	Flagged         int64
	TopViolations   map[string]int64
}

// NewBOLADetector creates a new BOLA detector.
func NewBOLADetector(cfg BOLAConfig, rdb *redis.Client) *BOLADetector {
	d := &BOLADetector{
		cfg:   cfg,
		rdb:   rdb,
		stats: &bolaStats{TopViolations: make(map[string]int64)},
	}
	if cfg.Enabled {
		d.enabled = 1
	}
	return d
}

// Precompiled at package init — avoids per-request MustCompile.
var bolaPathRE = regexp.MustCompile(`^/([a-zA-Z0-9_-]+)/([0-9]+)(?:/|$)`)

// Middleware returns HTTP middleware that detects potential IDOR.
func (d *BOLADetector) Middleware(next http.Handler) http.Handler {
	if atomic.LoadInt32(&d.enabled) == 0 {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && r.Method != "PUT" && r.Method != "DELETE" {
			next.ServeHTTP(w, r)
			return
		}

		match := bolaPathRE.FindStringSubmatch(r.URL.Path)
		if match == nil {
			next.ServeHTTP(w, r)
			return
		}

		resourceType := match[1]
		resourceID := match[2]
		claims := auth.ClaimsFromContext(r.Context())
		atomic.AddInt64(&d.stats.ChecksPerformed, 1)

		if claims != nil && claims.UserID != 0 && isUserScopedResource(resourceType) && claims.Role != "admin" {
			if resourceID != strconv.Itoa(claims.UserID) {
				d.recordViolation(resourceType, claims.UserID, resourceID)
				writeBlockError(w, "BOLA_BLOCKED", "possible broken object-level authorization")
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		ip := extractIP(r)
		if claims != nil && d.rdb != nil && ip != nil {
			ctx := context.Background()
			key := "bola:user:" + strconv.Itoa(claims.UserID) + ":" + resourceType
			d.rdb.SAdd(ctx, key, resourceID)
			d.rdb.Expire(ctx, key, 24*time.Hour)
			count, _ := d.rdb.SCard(ctx, key).Result()
			if count > int64(d.bolaThreshold()) {
				d.recordViolation(resourceType, claims.UserID, resourceID)
			}
		}

		next.ServeHTTP(w, r)
	})
}

func isUserScopedResource(resourceType string) bool {
	switch resourceType {
	case "users", "accounts", "profiles", "members", "customers":
		return true
	default:
		return false
	}
}

func (d *BOLADetector) bolaThreshold() int {
	if d.cfg.AnomalyThreshold >= 1 {
		return int(d.cfg.AnomalyThreshold)
	}
	return 3
}

func (d *BOLADetector) recordViolation(resourceType string, userID int, resourceID string) {
	atomic.AddInt64(&d.stats.Flagged, 1)
	d.stats.mu.Lock()
	d.stats.TopViolations[resourceType]++
	d.stats.mu.Unlock()
	log.Printf("bola: flagged user=%d resource=%s id=%s", userID, sanitizeLog(resourceType), sanitizeLog(resourceID))
}

// Stats returns current snapshot.
func (d *BOLADetector) Stats() map[string]interface{} {
	d.stats.mu.Lock()
	defer d.stats.mu.Unlock()

	top := make(map[string]int64, len(d.stats.TopViolations))
	for k, v := range d.stats.TopViolations {
		top[k] = v
	}

	return map[string]interface{}{
		"enabled":        atomic.LoadInt32(&d.enabled) == 1,
		"checks":         atomic.LoadInt64(&d.stats.ChecksPerformed),
		"flagged":        atomic.LoadInt64(&d.stats.Flagged),
		"top_violations": top,
	}
}
