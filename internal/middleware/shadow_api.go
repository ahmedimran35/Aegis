package middleware

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// ShadowAPIDiscoveryConfig holds configuration.
type ShadowAPIDiscoveryConfig struct {
	Enabled     bool
	MinReqCount int64
}

// DefaultShadowAPIDiscoveryConfig returns production defaults.
func DefaultShadowAPIDiscoveryConfig() ShadowAPIDiscoveryConfig {
	return ShadowAPIDiscoveryConfig{
		Enabled:     true,
		MinReqCount: 10,
	}
}

// ShadowAPIDiscovery discovers undocumented API endpoints from traffic.
type ShadowAPIDiscovery struct {
	enabled  int32
	cfg      ShadowAPIDiscoveryConfig
	stats    *shadowAPIStats
	rdb      *redis.Client
	stopCh   chan struct{}
	stopOnce sync.Once
}

type shadowAPIStats struct {
	mu               sync.Mutex
	Discovered       int64
	Flagged          int64
	TopEndpoints     map[string]int64
	FlaggedEndpoints map[string]int64
}

// NewShadowAPIDiscovery creates a new shadow API discovery engine.
func NewShadowAPIDiscovery(cfg ShadowAPIDiscoveryConfig, rdb *redis.Client) *ShadowAPIDiscovery {
	s := &ShadowAPIDiscovery{
		cfg:    cfg,
		rdb:    rdb,
		stopCh: make(chan struct{}),
		stats:  &shadowAPIStats{TopEndpoints: make(map[string]int64), FlaggedEndpoints: make(map[string]int64)},
	}
	if cfg.Enabled {
		s.enabled = 1
	}
	return s
}

// Start begins periodic aggregation of discovered endpoints.
func (s *ShadowAPIDiscovery) Start(ctx context.Context) {
	if atomic.LoadInt32(&s.enabled) == 0 || s.rdb == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.Scan(ctx)
			case <-s.stopCh:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
}

// Stop stops the background scanner.
func (s *ShadowAPIDiscovery) Stop() {
	s.stopOnce.Do(func() { close(s.stopCh) })
}

// Stats returns current snapshot.
func (s *ShadowAPIDiscovery) Stats() map[string]interface{} {
	s.stats.mu.Lock()
	defer s.stats.mu.Unlock()

	top := make(map[string]int64, len(s.stats.TopEndpoints))
	for k, v := range s.stats.TopEndpoints {
		top[k] = v
	}
	flagged := make(map[string]int64, len(s.stats.FlaggedEndpoints))
	for k, v := range s.stats.FlaggedEndpoints {
		flagged[k] = v
	}

	return map[string]interface{}{
		"enabled":           atomic.LoadInt32(&s.enabled) == 1,
		"discovered":        atomic.LoadInt64(&s.stats.Discovered),
		"flagged":           atomic.LoadInt64(&s.stats.Flagged),
		"top_endpoints":     top,
		"flagged_endpoints": flagged,
	}
}

// Scan aggregates per-endpoint request counts for shadow API detection.
// Call this periodically from a background worker.
func (s *ShadowAPIDiscovery) Scan(ctx context.Context) {
	if atomic.LoadInt32(&s.enabled) == 0 || s.rdb == nil {
		return
	}

	keys, err := s.rdb.Keys(ctx, "shadowapi:*").Result()
	if err != nil {
		return
	}

	top := make(map[string]int64, len(keys))
	flagged := make(map[string]int64)
	for _, key := range keys {
		count, err := s.rdb.Get(ctx, key).Int64()
		if err != nil {
			continue
		}
		endpoint := strings.TrimPrefix(key, "shadowapi:")
		top[endpoint] = count
		if count >= s.cfg.MinReqCount {
			flagged[endpoint] = count
		}
	}

	s.stats.mu.Lock()
	s.stats.TopEndpoints = top
	s.stats.FlaggedEndpoints = flagged
	s.stats.Discovered = int64(len(top))
	s.stats.Flagged = int64(len(flagged))
	s.stats.mu.Unlock()
}

func (s *ShadowAPIDiscovery) Middleware(next http.Handler) http.Handler {
	if atomic.LoadInt32(&s.enabled) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		endpoint := r.Method + " " + normalizeEndpointPath(r.URL.Path)
		if s.rdb != nil {
			key := "shadowapi:" + endpoint
			_ = s.rdb.Incr(r.Context(), key)
			_ = s.rdb.Expire(r.Context(), key, 24*time.Hour)
		}
		next.ServeHTTP(w, r)
	})
}

func normalizeEndpointPath(path string) string {
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if part == "" {
			continue
		}
		if _, err := strconv.Atoi(part); err == nil {
			parts[i] = "{id}"
		}
	}
	return strings.Join(parts, "/")
}
