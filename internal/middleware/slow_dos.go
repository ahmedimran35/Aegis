package middleware

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/redis/go-redis/v9"
	"github.com/user/waf/internal/util/lru"
)

// H-8: hard cap on the in-memory top-attackers map.
const defaultSlowDoSTopAttacking = 10000

// slowDoSLua atomically INCRs three window keys and refreshes their TTLs.
// Returning the new counter from Lua lets us read the value back without
// an additional round-trip. M-19.
var slowDoSLua = redis.NewScript(`
local n = tonumber(#KEYS)
for i = 1, n do
  local ttl = tonumber(ARGV[i])
  local cur = redis.call('INCR', KEYS[i])
  if ttl > 0 and cur == 1 then
    redis.call('EXPIRE', KEYS[i], ttl)
  end
  table.insert(_result, cur)
end
return _result
`)

// anyToIface converts []int64 (or []string, etc.) to []interface{} as
// required by redis.Script.Run / Eval.
func anyToIface[T any](v []T) []interface{} {
	out := make([]interface{}, len(v))
	for i := range v {
		out[i] = v[i]
	}
	return out
}

// SlowDoSConfig configures slow-rate DoS detection across multiple time windows.
type SlowDoSConfig struct {
	Enabled   bool
	Window1m  int    // max requests per 60s
	Window5m  int    // max requests per 300s
	Window15m int    // max requests per 900s
	Action    string // "challenge" | "block" | "log"
}

// DefaultSlowDoSConfig returns production-safe defaults.
func DefaultSlowDoSConfig() SlowDoSConfig {
	return SlowDoSConfig{
		Enabled:   true,
		Window1m:  120,
		Window5m:  500,
		Window15m: 1500,
		Action:    "challenge",
	}
}

// SlowDoSDetector tracks sustained request rates that bypass burst-based rate limiters.
type SlowDoSDetector struct {
	enabled int32
	cfg     SlowDoSConfig
	stats   *slowDoSStats
	rdb     *redis.Client
}

type slowDoSStats struct {
	mu              sync.Mutex
	Detected        int64
	Blocked         int64
	Challenged      int64
	// H-8: bounded LRU map replaces the previous unbounded map.
	TopAttackingIPs *lru.LRU[string, int64]
}

type slowDoSStatsSnapshot struct {
	Enabled         bool             `json:"enabled"`
	Detected        int64            `json:"detected"`
	Blocked         int64            `json:"blocked"`
	Challenged      int64            `json:"challenged"`
	Window1m        int              `json:"window_1m"`
	Window5m        int              `json:"window_5m"`
	Window15m       int              `json:"window_15m"`
	TopAttackingIPs map[string]int64 `json:"top_attacking_ips"`
}

// NewSlowDoSDetector creates a new slow-rate DoS detector.
func NewSlowDoSDetector(cfg SlowDoSConfig, rdb *redis.Client) *SlowDoSDetector {
	switch cfg.Action {
	case "block", "challenge", "log":
	default:
		cfg.Action = "challenge"
	}
	d := &SlowDoSDetector{
		cfg: cfg,
		rdb: rdb,
		stats: &slowDoSStats{
			TopAttackingIPs: lru.New[string, int64](defaultSlowDoSTopAttacking),
		},
	}
	if cfg.Enabled {
		d.enabled = 1
	}
	return d
}

// Middleware returns HTTP middleware for slow-rate DoS detection.
func (d *SlowDoSDetector) Middleware(next http.Handler) http.Handler {
	if atomic.LoadInt32(&d.enabled) == 0 || d.rdb == nil {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r)
		if ip == nil {
			next.ServeHTTP(w, r)
			return
		}
		ipStr := ip.String()
		ctx := r.Context()

		violation, window := d.checkWindows(ctx, ipStr)
		if !violation {
			next.ServeHTTP(w, r)
			return
		}

		atomic.AddInt64(&d.stats.Detected, 1)
		d.stats.TopAttackingIPs.Add(ipStr, 1)

		switch d.cfg.Action {
		case "block":
			atomic.AddInt64(&d.stats.Blocked, 1)
			log.Printf("slow_dos: BLOCKED %s window=%s", sanitizeLog(ipStr), window)
			writeBlockError(w, "SLOW_DOS_BLOCKED", "sustained request rate exceeds threshold")
			return
		case "challenge":
			atomic.AddInt64(&d.stats.Challenged, 1)
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"RATE_LIMITED","message":"request rate exceeded"}`))
			return
		default:
			if m := MetricsFromContext(ctx); m != nil {
				m.AIClassification = "suspicious"
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (d *SlowDoSDetector) checkWindows(ctx context.Context, ip string) (bool, string) {
	windows := []struct {
		name      string
		seconds   int
		threshold int
	}{
		{"1m", 60, d.cfg.Window1m},
		{"5m", 300, d.cfg.Window5m},
		{"15m", 900, d.cfg.Window15m},
	}

	counts := make(map[string]int64, len(windows))
	// M-19: collapse the 6 Redis round-trips into a single Lua call.
	// The script receives KEYS={key1,key2,key3} and ARGV={ttl1,ttl2,ttl3}
	// and returns the incremented counter for each key, refreshing the
	// TTL atomically (only when a non-zero TTL is provided).
	keys := make([]string, 0, len(windows))
	ttls := make([]int64, 0, len(windows))
	for _, window := range windows {
		if window.threshold <= 0 {
			continue
		}
		keys = append(keys, fmt.Sprintf("slowdos:%s:%s", window.name, ip))
		ttls = append(ttls, int64(window.seconds))
	}
	if len(keys) > 0 {
		res, err := slowDoSLua.Run(ctx, d.rdb, keys, anyToIface(ttls)...).Result()
		if err != nil {
			log.Printf("slow_dos: redis error: %v", err)
		} else if arr, ok := res.([]interface{}); ok {
			for i, v := range arr {
				if i >= len(windows) {
					break
				}
				if n, ok := v.(int64); ok {
					counts[windows[i].name] = n
				}
			}
		}
	}

	for _, window := range windows {
		if window.threshold <= 0 {
			continue
		}
		if counts[window.name] > int64(window.threshold) {
			return true, window.name
		}
	}
	return false, ""
}

func (d *SlowDoSDetector) Stats() slowDoSStatsSnapshot {
	top := d.stats.TopAttackingIPs.Snapshot()
	return slowDoSStatsSnapshot{
		Enabled:         atomic.LoadInt32(&d.enabled) == 1,
		Detected:        atomic.LoadInt64(&d.stats.Detected),
		Blocked:         atomic.LoadInt64(&d.stats.Blocked),
		Challenged:      atomic.LoadInt64(&d.stats.Challenged),
		Window1m:        d.cfg.Window1m,
		Window5m:        d.cfg.Window5m,
		Window15m:       d.cfg.Window15m,
		TopAttackingIPs: top,
	}
}
