package ai

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// CostController enforces per-user/per-IP token and request budgets over a
// rolling window. When exceeded, calls return ErrBudgetExceeded and callers
// must treat the request as fail-closed (do NOT proceed without AI verdict).
type CostController struct {
	// MaxTokensPerHour is the maximum AI tokens one caller may consume per hour.
	MaxTokensPerHour int64
	// MaxCallsPerMin is the maximum AI calls per minute (rate limit).
	MaxCallsPerMin int64
	// FailClosed indicates budget exhaustion returns ErrBudgetExceeded (true)
	// vs degraded fallback (false). Default true.
	FailClosed bool

	mu          sync.Mutex
	tokensByKey map[string]*tokenBucket
	callsByKey  map[string]*callBucket

	// H-9: TTL on bucket entries so an attacker who rotates keys can not
	// grow the map without bound. lastSeen tracks the wall-clock time of
	// the most recent Allow() call; any key idle for more than
	// bucketIdleTTL is evicted by the sweeper.
	bucketIdleTTL time.Duration

	// H-9: lifecycle for the sweeper goroutine. Stop() closes stopCh and
	// waits on doneCh.
	stopCh chan struct{}
	doneCh chan struct{}
	once   sync.Once
}

// ErrBudgetExceeded is returned by Allow when the caller has exhausted budget.
var ErrBudgetExceeded = errBudget("ai budget exceeded")

type errBudget string

func (e errBudget) Error() string { return string(e) }

// NewCostController with sensible defaults: 100k tokens/hour, 60 calls/min, fail-closed.
func NewCostController() *CostController {
	c := &CostController{
		MaxTokensPerHour: 100_000,
		MaxCallsPerMin:   60,
		FailClosed:       true,
		bucketIdleTTL:    30 * time.Minute,
		tokensByKey:      make(map[string]*tokenBucket),
		callsByKey:       make(map[string]*callBucket),
		stopCh:           make(chan struct{}),
		doneCh:           make(chan struct{}),
	}
	go c.sweepLoop()
	return c
}

// Stop terminates the background sweeper and is safe to call multiple times.
func (c *CostController) Stop() {
	c.once.Do(func() {
		close(c.stopCh)
		<-c.doneCh
	})
}

// sweepLoop evicts token+call buckets whose lastSeen is older than
// bucketIdleTTL. Without eviction, a key-rotating attacker can grow
// tokensByKey and callsByKey without bound (M-3).
func (c *CostController) sweepLoop() {
	defer close(c.doneCh)
	defer func() {
		if r := recover(); r != nil {
			log.Printf("ai: CostController sweepLoop panic recovered: %v", r)
		}
	}()
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.sweepOnce()
		}
	}
}

func (c *CostController) sweepOnce() {
	c.mu.Lock()
	defer c.mu.Unlock()
	cutoff := time.Now().Add(-c.bucketIdleTTL)
	for k, tb := range c.tokensByKey {
		if tb.lastSeen.Before(cutoff) {
			delete(c.tokensByKey, k)
			delete(c.callsByKey, k)
		}
	}
}

// Allow checks whether the caller identified by key may invoke AI with the
// given estimated token cost. Returns ErrBudgetExceeded if rejected.
func (c *CostController) Allow(_ context.Context, key string, estTokens int64) error {
	if c.FailClosed {
		// two-phase check; token bucket first (more expensive failure)
		if !c.allowTokens(key, estTokens) {
			return ErrBudgetExceeded
		}
		if !c.allowCall(key) {
			// refund the tokens we tentatively reserved
			c.refundTokens(key, estTokens)
			return ErrBudgetExceeded
		}
		return nil
	}
	// fail-open: still record the attempt, but allow the request through.
	// The previous code returned nil (allowed) on BOTH paths — when
	// allowTokens was true and when it was false — making the "fail-open"
	// branch indistinguishable from "allow". Now we log when budget is
	// exceeded so operators can see abuse even in fail-open mode.
	if !c.allowTokens(key, estTokens) || !c.allowCall(key) {
		log.Printf("ai: budget exceeded for key=%s (fail-open, allowing)", key)
		return nil
	}
	return nil
}

// AllowAndCharge records an actual token cost AFTER a successful call. Pair
// with Allow that pre-reserved estTokens.
func (c *CostController) AllowAndCharge(key string, estTokens, actualTokens int64) {
	c.mu.Lock()
	tb := c.tokensByKey[key]
	c.mu.Unlock()
	if tb == nil {
		return
	}
	// adjust reservation toward actual usage
	diff := actualTokens - estTokens
	if diff > 0 {
		tb.consume(diff)
	} else if diff < 0 {
		tb.refund(-diff)
	}
}

func (c *CostController) allowTokens(key string, n int64) bool {
	c.mu.Lock()
	tb, ok := c.tokensByKey[key]
	if !ok {
		tb = &tokenBucket{window: time.Hour}
		c.tokensByKey[key] = tb
	}
	c.mu.Unlock()
	return tb.consume(n)
}

func (c *CostController) allowCall(key string) bool {
	c.mu.Lock()
	cb, ok := c.callsByKey[key]
	if !ok {
		cb = &callBucket{window: time.Minute, max: c.MaxCallsPerMin}
		c.callsByKey[key] = cb
	}
	c.mu.Unlock()
	return cb.allow()
}

func (c *CostController) refundTokens(key string, n int64) {
	c.mu.Lock()
	tb := c.tokensByKey[key]
	c.mu.Unlock()
	if tb != nil {
		tb.refund(n)
	}
}

// Stats returns a snapshot of all buckets for /metrics.
func (c *CostController) Stats() map[string]interface{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	tokens := make(map[string]int64, len(c.tokensByKey))
	calls := make(map[string]int64, len(c.callsByKey))
	for k, tb := range c.tokensByKey {
		tokens[k] = tb.used
	}
	for k, cb := range c.callsByKey {
		calls[k] = cb.used
	}
	return map[string]interface{}{
		"max_tokens_per_hour": c.MaxTokensPerHour,
		"max_calls_per_min":   c.MaxCallsPerMin,
		"fail_closed":         c.FailClosed,
		"tracked_keys":        len(c.tokensByKey),
		"tokens":              tokens,
		"calls":               calls,
	}
}

// --- token bucket: rolling window with atomic accounting ---

type tokenBucket struct {
	window   time.Duration
	mu       sync.Mutex
	used     int64
	reset    time.Time
	lastSeen time.Time
}

// consume applies n tokens against this bucket. The wall-clock value is
// read from time.Now() exactly once per call so the comparison is
// monotonic within the locked region.
//
// P-FIX (M-26): the clock is a single source (no caller-provided time
// argument) to avoid the "caller clock drift" audit finding. Buckets
// roll over independently using this single value.
func (b *tokenBucket) consume(n int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	b.lastSeen = now
	if now.After(b.reset) || b.reset.IsZero() {
		b.used = 0
		b.reset = now.Add(b.window)
	}
	if b.used+n > 1<<32 {
		// overflow safety: clamp
		b.used = 1 << 32
		return false
	}
	b.used += n
	return true
}

func (b *tokenBucket) refund(n int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if n >= b.used {
		b.used = 0
		return
	}
	b.used -= n
}

// --- call bucket: simple per-minute counter with reset ---

type callBucket struct {
	window   time.Duration
	max      int64
	mu       sync.Mutex
	used     int64
	reset    time.Time
	lastSeen time.Time
}

func (b *callBucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	b.lastSeen = now
	if now.After(b.reset) || b.reset.IsZero() {
		atomic.StoreInt64(&b.used, 0)
		b.reset = now.Add(b.window)
	}
	if b.used >= b.max {
		return false
	}
	b.used++
	return true
}
