package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// AnomalyDetector runs periodic anomaly detection in the background.
type AnomalyDetector struct {
	ai       *Router
	rdb      *redis.Client
	pool     *pgxpool.Pool
	stopCh   chan struct{}
	stopOnce sync.Once

	// ErrFailClosedWhenStatsUnavailable: when true (recommended), the detector
	// refuses to emit any anomaly on a cycle where Redis stats are unavailable.
	// Reasoning: zero-valued stats (no Redis responses) look identical to a
	// perfectly quiet network, which is a false-negative. Better to report
	// no anomaly + log loudly than to emit a fake-green cycle.
	ErrFailClosedWhenStatsUnavailable bool
}

// NewAnomalyDetector creates a background anomaly detector. Defaults to
// fail-CLOSED behavior when stats are unavailable.
func NewAnomalyDetector(ai *Router, rdb *redis.Client, pool *pgxpool.Pool) *AnomalyDetector {
	return &AnomalyDetector{
		ai:                                  ai,
		rdb:                                 rdb,
		pool:                                pool,
		stopCh:                              make(chan struct{}),
		ErrFailClosedWhenStatsUnavailable:   true,
	}
}

// Start begins the anomaly detection loop (every 5 minutes).
func (d *AnomalyDetector) Start() {
	go d.run()
}

func (d *AnomalyDetector) run() {
	// Run immediately on start
	d.detect()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			d.detect()
		case <-d.stopCh:
			return
		}
	}
}

func (d *AnomalyDetector) detect() {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	stats, err := d.collectStats(ctx)
	if err != nil {
		if d.ErrFailClosedWhenStatsUnavailable {
			log.Printf("anomaly: stats unavailable, skipping cycle (fail-CLOSED): %v", err)
			return
		}
		log.Printf("anomaly: collect stats: %v", err)
		return
	}

	result, err := d.ai.DetectAnomaly(ctx, *stats)
	if err != nil {
		log.Printf("anomaly: detect: %v", err)
		return
	}

	if result.HasAnomaly {
		for _, a := range result.Anomalies {
			d.storeAnomaly(ctx, a)
		}
		log.Printf("anomaly: detected %d anomalies", len(result.Anomalies))
	}
}

func (d *AnomalyDetector) collectStats(ctx context.Context) (*TrafficStats, error) {
	total, err := d.rdb.Get(ctx, "stats:requests:total").Int64()
	if err != nil && err != redis.Nil {
		return nil, fmt.Errorf("stats:requests:total: %w", err)
	}
	// P-FIX: distinguish "no traffic seen yet" (redis.Nil) from a
	// functioning Redis. Previously redis.Nil returned 0 silently, which
	// is indistinguishable from "stats:requests:total" being genuinely 0
	// (a real quiet network). We now tag the result as Degraded so the
	// detector can refuse to emit a fake-green anomaly.
	degraded := err == redis.Nil
	if degraded {
		log.Printf("anomaly: stats:requests:total missing — treating cycle as degraded (fail-closed)")
	}
	blocked, err := d.rdb.Get(ctx, "stats:requests:blocked").Int64()
	if err != nil && err != redis.Nil {
		return nil, fmt.Errorf("stats:requests:blocked: %w", err)
	}
	if err == redis.Nil {
		degraded = true
	}

	// Top IPs from sorted set
	topIPsRaw, err := d.rdb.ZRevRangeWithScores(ctx, "stats:top_ips", 0, 9).Result()
	if err != nil && err != redis.Nil {
		return nil, fmt.Errorf("stats:top_ips: %w", err)
	}
	if err == redis.Nil {
		degraded = true
	}
	topIPs := make(map[string]int64)
	for _, z := range topIPsRaw {
		if s, ok := z.Member.(string); ok {
			topIPs[s] = int64(z.Score)
		}
	}

	// Top endpoints
	topEndpointsRaw, err := d.rdb.ZRevRangeWithScores(ctx, "stats:top_endpoints", 0, 9).Result()
	if err != nil && err != redis.Nil {
		return nil, fmt.Errorf("stats:top_endpoints: %w", err)
	}
	if err == redis.Nil {
		degraded = true
	}
	topEndpoints := make(map[string]int64)
	for _, z := range topEndpointsRaw {
		if s, ok := z.Member.(string); ok {
			topEndpoints[s] = int64(z.Score)
		}
	}

	return &TrafficStats{
		TotalRequests:   total,
		BlockedRequests: blocked,
		TopIPs:          topIPs,
		TopEndpoints:    topEndpoints,
		TimeWindow:      "5m",
		DegradedCycle:   degraded,
	}, nil
}

func (d *AnomalyDetector) storeAnomaly(ctx context.Context, a Anomaly) {
	ctxJSON, _ := json.Marshal(map[string]interface{}{
		"type":       a.Type,
		"confidence": a.Confidence,
	})

	_, err := d.pool.Exec(ctx,
		`INSERT INTO anomalies (type, severity, description, context) VALUES ($1, $2, $3, $4)`,
		a.Type, a.Severity, a.Description, ctxJSON,
	)
	if err != nil {
		log.Printf("anomaly: store: %v", err)
	}
}

// Stop halts the background detection loop.
func (d *AnomalyDetector) Stop() {
	d.stopOnce.Do(func() { close(d.stopCh) })
}
