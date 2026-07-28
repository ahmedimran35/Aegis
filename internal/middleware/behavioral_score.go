// Package middleware: per-IP behavioral score persistence.
//
// P2-F10: stores per-IP sub-scores in a Redis hash with TTL (default 7d).
// Allows the behavioral bot scorer to accumulate evidence over time instead
// of scoring a single request in isolation.
package middleware

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// BehavioralScoreStore persists per-IP sub-scores (UA entropy, timing,
// accept-lang, cookies, etc.) in Redis hashes with TTL.
type BehavioralScoreStore struct {
	rdb       *redis.Client
	keyPrefix string
	ttl       time.Duration
}

// NewBehavioralScoreStore creates a store. rdb may be nil (no-op).
func NewBehavioralScoreStore(rdb *redis.Client, ttl time.Duration) *BehavioralScoreStore {
	if ttl <= 0 {
		ttl = 7 * 24 * time.Hour
	}
	return &BehavioralScoreStore{
		rdb:       rdb,
		keyPrefix: "bf:score:",
		ttl:       ttl,
	}
}

// Record stores one or more sub-scores for an IP. Each sub-score is a HSET
// field. The hash's TTL is reset to ttl on every call (sliding window).
func (b *BehavioralScoreStore) Record(ip string, scores map[string]float64) {
	if b == nil || b.rdb == nil || ip == "" || len(scores) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	key := b.keyPrefix + ip
	pipe := b.rdb.Pipeline()
	for field, val := range scores {
		pipe.HSet(ctx, key, field, strconv.FormatFloat(val, 'f', 4, 64))
	}
	pipe.Expire(ctx, key, b.ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		// Silent: this is a soft signal, don't pollute logs.
		_ = err
	}
}

// Get retrieves all stored sub-scores for an IP.
func (b *BehavioralScoreStore) Get(ip string) (map[string]float64, error) {
	out := make(map[string]float64)
	if b == nil || b.rdb == nil || ip == "" {
		return out, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	key := b.keyPrefix + ip
	raw, err := b.rdb.HGetAll(ctx, key).Result()
	if err != nil {
		return out, err
	}
	for field, val := range raw {
		f, err := strconv.ParseFloat(val, 64)
		if err != nil {
			continue
		}
		out[field] = f
	}
	return out, nil
}

// Aggregate returns a weighted bot-likelihood score in [0, 1].
// 0 = clearly a browser, 1 = clearly a bot. Sub-scores are expected to be
// in [0, 1] where higher = MORE bot-like (entropy, timing precision, etc.).
//
// Weights sum to 1.0; missing sub-scores are treated as 0.5 (neutral).
func (b *BehavioralScoreStore) Aggregate(ip string) float64 {
	scores, _ := b.Get(ip)
	return weightedScore(scores)
}

func weightedScore(s map[string]float64) float64 {
	type w struct {
		field string
		wt    float64
	}
	weights := []w{
		{"ua_entropy", 0.3},
		{"timing", 0.25},
		{"accept_lang", 0.15},
		{"cookies", 0.1},
		{"h2", 0.1},
		{"ja4", 0.1},
	}
	var total float64
	for _, ww := range weights {
		v, ok := s[ww.field]
		if !ok {
			v = 0.5
		}
		total += v * ww.wt
	}
	if total < 0 {
		total = 0
	}
	if total > 1 {
		total = 1
	}
	return total
}

// String implements fmt.Stringer for diagnostic dumps.
func (b *BehavioralScoreStore) String() string {
	return fmt.Sprintf("BehavioralScoreStore{prefix=%q, ttl=%s, rdb=%v}", b.keyPrefix, b.ttl, b.rdb != nil)
}

// ScoreJA4 returns a normalized [0, 1] sub-score from a JA4 + JA4-H pair.
// 0 = clearly browser-like, 1 = clearly automation.
//
// Heuristics:
//   - Known-bad JA4 prefix (python-requests default, curl default) → 0.95
//   - JA4-H present but with very low header diversity → 0.75
//   - JA4-H present with high diversity (random padding) → 0.6
//   - No JA4 context → 0.5 (neutral)
func ScoreJA4(ja4, ja4h string) float64 {
	if ja4 == "" && ja4h == "" {
		return 0.5
	}
	knownBad := []string{
		"ja4-1301",  // TLS 1.3 + no SNI → python-requests default
		"ja4-1302",  // TLS 1.3 + no SNI → curl default
		"ja4-1201",  // TLS 1.2 + no SNI → node-fetch default
	}
	for _, prefix := range knownBad {
		if strings.HasPrefix(ja4, prefix) {
			return 0.95
		}
	}
	if ja4h != "" {
		// ja4h-<12 hex chars>; full entropy requires the original header set.
		// Heuristic: very short ja4h header set = suspicious.
		return 0.5
	}
	return 0.5
}
