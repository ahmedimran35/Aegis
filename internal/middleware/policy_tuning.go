package middleware

import (
	"context"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// PolicyTunerConfig holds configuration for per-endpoint policy tuning.
type PolicyTunerConfig struct {
	Enabled        bool
	MinSamples     int
	AdjustmentStep float64
	MinThreshold   int
	MaxThreshold   int
	Retention      time.Duration
	FPWeight       float64
	FNWeight       float64
}

// DefaultPolicyTunerConfig returns safe production defaults.
func DefaultPolicyTunerConfig() PolicyTunerConfig {
	return PolicyTunerConfig{
		Enabled:        false,
		MinSamples:     100,
		AdjustmentStep: 0.5,
		MinThreshold:   3,
		MaxThreshold:   50,
		Retention:      24 * time.Hour,
		FPWeight:       1.0,
		FNWeight:       2.0,
	}
}

// PolicyTuner adjusts anomaly thresholds per endpoint based on feedback.
type PolicyTuner struct {
	enabled int32
	cfg     PolicyTunerConfig
	rdb     *redis.Client
	stopCh  chan struct{}
}

// NewPolicyTuner creates a new policy tuner.
func NewPolicyTuner(cfg PolicyTunerConfig, rdb *redis.Client) *PolicyTuner {
	t := &PolicyTuner{cfg: cfg, rdb: rdb, stopCh: make(chan struct{})}
	if cfg.Enabled {
		t.enabled = 1
		go t.loop()
	}
	return t
}

// GetThreshold returns the current threshold for a path.
func (t *PolicyTuner) GetThreshold(path string) int {
	if atomic.LoadInt32(&t.enabled) == 0 || t.rdb == nil {
		return 0
	}
	key := "policy:tuner:" + pathPrefix(path) + ":threshold"
	val, err := t.rdb.Get(context.Background(), key).Result()
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(val)
	return n
}

// RecordFP records a false positive for a path.
func (t *PolicyTuner) RecordFP(path string) {
	if atomic.LoadInt32(&t.enabled) == 0 || t.rdb == nil {
		return
	}
	prefix := pathPrefix(path)
	key := "policy:tuner:" + prefix
	pipe := t.rdb.Pipeline()
	pipe.Incr(context.Background(), key+":fp")
	pipe.Incr(context.Background(), key+":total")
	pipe.Expire(context.Background(), key+":fp", t.cfg.Retention)
	pipe.Expire(context.Background(), key+":total", t.cfg.Retention)
	pipe.Exec(context.Background())
}

// RecordFN records a false negative for a path.
func (t *PolicyTuner) RecordFN(path string) {
	if atomic.LoadInt32(&t.enabled) == 0 || t.rdb == nil {
		return
	}
	prefix := pathPrefix(path)
	key := "policy:tuner:" + prefix
	pipe := t.rdb.Pipeline()
	pipe.Incr(context.Background(), key+":fn")
	pipe.Incr(context.Background(), key+":total")
	pipe.Expire(context.Background(), key+":fn", t.cfg.Retention)
	pipe.Expire(context.Background(), key+":total", t.cfg.Retention)
	pipe.Exec(context.Background())
}

func (t *PolicyTuner) loop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			t.adjustAll()
		case <-t.stopCh:
			return
		}
	}
}

// Stop stops the background adjustment loop.
func (t *PolicyTuner) Stop() {
	if atomic.LoadInt32(&t.enabled) == 0 {
		return
	}
	select {
	case <-t.stopCh:
		return
	default:
		close(t.stopCh)
	}
}

// Stats returns a snapshot of tuner counters.
func (t *PolicyTuner) Stats() map[string]interface{} {
	if t == nil {
		return map[string]interface{}{"enabled": false}
	}
	return map[string]interface{}{
		"enabled":         atomic.LoadInt32(&t.enabled) == 1,
		"min_samples":     t.cfg.MinSamples,
		"adjustment_step": t.cfg.AdjustmentStep,
		"min_threshold":   t.cfg.MinThreshold,
		"max_threshold":   t.cfg.MaxThreshold,
		"fp_weight":       t.cfg.FPWeight,
		"fn_weight":       t.cfg.FNWeight,
	}
}

func (t *PolicyTuner) adjustAll() {
	if t.rdb == nil {
		return
	}
	keys, err := t.rdb.Keys(context.Background(), "policy:tuner:*:total").Result()
	if err != nil {
		return
	}
	for _, key := range keys {
		prefix := strings.TrimSuffix(key, ":total")
		fp, _ := t.rdb.Get(context.Background(), prefix+":fp").Int64()
		fn, _ := t.rdb.Get(context.Background(), prefix+":fn").Int64()
		total, _ := t.rdb.Get(context.Background(), key).Int64()
		if total < int64(t.cfg.MinSamples) {
			continue
		}
		fpRate := float64(fp) / float64(total)
		fnRate := float64(fn) / float64(total)
		adj := int(t.cfg.AdjustmentStep * (fnRate*t.cfg.FNWeight - fpRate*t.cfg.FPWeight))
		cur, _ := t.rdb.Get(context.Background(), prefix+":threshold").Int()
		cur += adj
		if cur < t.cfg.MinThreshold {
			cur = t.cfg.MinThreshold
		}
		if cur > t.cfg.MaxThreshold {
			cur = t.cfg.MaxThreshold
		}
		t.rdb.Set(context.Background(), prefix+":threshold", cur, t.cfg.Retention)
	}
}

// pathPrefix returns a coarse key for the policy tuner.
//
// F32: previous implementation used parts[:3] which meant every
// `/api/v1/*` request was grouped into the single key "/api/v1". A
// noisy endpoint (`/api/v1/search`) would crank the threshold for
// unrelated endpoints (`/api/v1/login`). Using parts[:4] gives
// per-resource grouping without exploding the keyspace.
func pathPrefix(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) <= 4 {
		return path
	}
	return strings.Join(parts[:4], "/")
}
