package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/redis/go-redis/v9"
	wafmw "github.com/user/waf/internal/middleware"
)

// LibInjectionHandler serves libinjection stats via the API.
type LibInjectionHandler struct {
	stats *wafmw.LibInjectionStats
	rdb   *redis.Client
}

// NewLibInjectionHandler creates a new handler.
func NewLibInjectionHandler(stats *wafmw.LibInjectionStats, rdb *redis.Client) *LibInjectionHandler {
	return &LibInjectionHandler{stats: stats, rdb: rdb}
}

// Stats returns current libinjection statistics.
func (h *LibInjectionHandler) Stats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get Redis counters for recent detections
	sqliBlocked := h.getInt64(ctx, "stats:libinjection:sqli_blocked")
	xssBlocked := h.getInt64(ctx, "stats:libinjection:xss_blocked")

	recentDetections := h.getRecentDetections(ctx)

	data := map[string]interface{}{
		"requests_scanned":  h.stats.RequestsScanned.Load(),
		"sqli_blocked":      maxInt64(h.stats.SQLIBlocked.Load(), sqliBlocked),
		"xss_blocked":       maxInt64(h.stats.XSSBlocked.Load(), xssBlocked),
		"sqli_detected":     h.stats.SQLIDetected.Load(),
		"xss_detected":      h.stats.XSSDetected.Load(),
		"recent_detections": recentDetections,
	}

	RespondJSON(w, http.StatusOK, data)
}

func (h *LibInjectionHandler) getInt64(ctx context.Context, key string) int64 {
	v, err := h.rdb.Get(ctx, key).Int64()
	if err != nil {
		return 0
	}
	return v
}

func (h *LibInjectionHandler) getRecentDetections(ctx context.Context) []map[string]string {
	items, err := h.rdb.LRange(ctx, "stats:libinjection:recent", 0, 19).Result()
	if err != nil {
		return nil
	}
	var detections []map[string]string
	for _, item := range items {
		var d map[string]string
		if json.Unmarshal([]byte(item), &d) == nil {
			detections = append(detections, d)
		}
	}
	return detections
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
