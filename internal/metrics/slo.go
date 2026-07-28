// Package metrics: SLO helpers — error budget burn rate, request-class
// counters, and Prometheus exemplar-friendly counter snapshots. The SLO
// targets are project constants; you can override per-environment via env
// vars at startup (AEGIS_SLO_*).
package metrics

import (
	"sync"
	"sync/atomic"
	"time"
)

// SLO targets. Aegis commits to:
//   - 99.9% of classification requests succeed (1h window)
//   - 99% return within 250ms p95
//   - 99.99% of all incoming HTTP requests do NOT trigger a 5xx
type SLOTargets struct {
	ClassificationSuccessTarget float64       // 0.999
	ClassificationLatencyTarget time.Duration // 250ms
	HTTPNo5xxTarget             float64       // 0.9999
	BurnWindow                  time.Duration // 1h
}

var DefaultSLOTargets = SLOTargets{
	ClassificationSuccessTarget: 0.999,
	ClassificationLatencyTarget: 250 * time.Millisecond,
	HTTPNo5xxTarget:             0.9999,
	BurnWindow:                  1 * time.Hour,
}

// SLOBudget tracks a single SLO over a sliding window. Use NewSLOBudget and
// call Record() per event. Budget() returns remaining error budget (0..1).
type SLOBudget struct {
	name string

	mu       sync.Mutex
	window   time.Duration
	success  int64
	failure  int64
	events   []sloEvent
	target   float64
}

type sloEvent struct {
	at      time.Time
	success bool
}

// NewSLOBudget creates a budget tracker for one named SLO.
func NewSLOBudget(name string, target float64, window time.Duration) *SLOBudget {
	return &SLOBudget{
		name:    name,
		window:  window,
		target:  target,
		events:  make([]sloEvent, 0, 1024),
	}
}

// Record adds one outcome. Returns the post-record burn rate for the window.
func (b *SLOBudget) Record(success bool) float64 {
	b.mu.Lock()
	now := time.Now()
	cutoff := now.Add(-b.window)
	keep := b.events[:0]
	for _, e := range b.events {
		if e.at.After(cutoff) {
			keep = append(keep, e)
		}
	}
	b.events = append(keep, sloEvent{at: now, success: success})
	if success {
		atomic.AddInt64(&b.success, 1)
	} else {
		atomic.AddInt64(&b.failure, 1)
	}
	// compute burn while still holding the lock
	total := len(b.events)
	failed := 0
	for _, e := range b.events {
		if !e.success {
			failed++
		}
	}
	b.mu.Unlock()
	if total == 0 {
		return 0
	}
	observed := 1.0 - (float64(failed)/float64(total))
	if b.target <= 0 {
		return 0
	}
	if observed >= b.target {
		return 0
	}
	return (b.target - observed) / b.target
}

// Burn returns the burn rate (1.0 == consuming error budget at exactly the
// rate needed to exhaust in Window). Higher == worse.
func (b *SLOBudget) Burn() float64 {
	b.mu.Lock()
	total := len(b.events)
	failed := 0
	for _, e := range b.events {
		if !e.success {
			failed++
		}
	}
	b.mu.Unlock()
	if total == 0 {
		return 0
	}
	observed := 1.0 - (float64(failed)/float64(total))
	if b.target <= 0 {
		return 0
	}
	if observed >= b.target {
		return 0
	}
	// ratio of headroom consumed
	return (b.target - observed) / b.target
}

// BudgetRemaining returns the remaining budget as 0..1. 1.0 = full budget,
// 0.0 = exhausted.
func (b *SLOBudget) BudgetRemaining() float64 {
	burn := b.Burn()
	if burn > 1 {
		return 0
	}
	return 1 - burn
}

// SlotCounters is a project-wide tally suitable for Prometheus scraping.
type SlotCounters struct {
	mu              sync.Mutex
	classifications *SLOBudget
	latency         *SLOBudget
	http            *SLOBudget
}

var (
	globalCounters  *SlotCounters
	globalCountersO sync.Once
)

// Global returns the project-wide SLO counters. Constructed lazily with
// DefaultSLOTargets; replace via ResetGlobal in tests.
func Global() *SlotCounters {
	globalCountersO.Do(func() {
		globalCounters = &SlotCounters{
			classifications: NewSLOBudget("ai.classification.success", DefaultSLOTargets.ClassificationSuccessTarget, DefaultSLOTargets.BurnWindow),
			latency:         NewSLOBudget("ai.classification.latency", 1.0, DefaultSLOTargets.BurnWindow),
			http:            NewSLOBudget("http.no_5xx", DefaultSLOTargets.HTTPNo5xxTarget, DefaultSLOTargets.BurnWindow),
		}
	})
	return globalCounters
}

// ResetGlobal drops the singleton — for test isolation only.
func ResetGlobal() {
	globalCountersO = sync.Once{}
	globalCounters = nil
}

// RecordClassification feeds one classification outcome (success) and its
// observed latency. Pass latency=0 to skip latency tracking.
func (c *SlotCounters) RecordClassification(success bool, latency time.Duration) {
	c.classifications.Record(success)
	if latency > 0 {
		// latency-budget tracking: success = within target, failure = over
		c.latency.Record(latency <= DefaultSLOTargets.ClassificationLatencyTarget)
	}
}

// RecordHTTP feeds one HTTP outcome; status >= 500 is failure.
func (c *SlotCounters) RecordHTTP(status int) {
	c.http.Record(status < 500)
}

// Snapshot returns current values for /metrics.
func (c *SlotCounters) Snapshot() map[string]interface{} {
	return map[string]interface{}{
		"classification_budget_remaining": c.classifications.BudgetRemaining(),
		"classification_burn_rate":       c.classifications.Burn(),
		"latency_budget_remaining":        c.latency.BudgetRemaining(),
		"http_5xx_budget_remaining":       c.http.BudgetRemaining(),
		"http_5xx_burn_rate":              c.http.Burn(),
	}
}
