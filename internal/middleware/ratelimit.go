package middleware

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/user/waf/internal/auth"
)

// rateLimitScript is an atomic Lua script for fixed-window rate limiting.
// (Implementation is fixed-window; see audit note in NewRateLimiter — true
// sliding-window requires a sorted-set implementation.)
// KEYS[1] = rate limit key
// ARGV[1] = max requests, ARGV[2] = window seconds
// Returns: {allowed (0/1), remaining, retry_after}
//
// L-7: the previous implementation accepted `now` from Go via ARGV[3],
// which meant the bucket window was anchored to the Go process clock
// rather than the Redis server's clock. Drift between the two skewed the
// effective window. We now call redis.call('TIME') inside the script
// and ignore the Go-supplied value (kept in ARGV[3] for back-compat).
//
// L-8: deprecated HMSET replaced with HSET field-value pairs.
var rateLimitScript = redis.NewScript(`
local key = KEYS[1]
local max = tonumber(ARGV[1])
local window = tonumber(ARGV[2])

-- L-7: derive now from the Redis server clock to avoid drift between
-- the Go process and Redis.
local t = redis.call('TIME')
local now = tonumber(t[1])

local info = redis.call('HMGET', key, 'count', 'window_start')
local count = tonumber(info[1]) or 0
local window_start = tonumber(info[2]) or 0

if now - window_start >= window then
    count = 0
    window_start = now
end

if count >= max then
    local retry_after = window - (now - window_start)
    -- P-FIX: clamp to non-negative. If the script fires right at the
    -- boundary, retry_after can go negative and the Go side would set
    -- a negative Retry-After header which some clients reject.
    if retry_after < 0 then retry_after = 0 end
    return {0, 0, retry_after}
end

count = count + 1
-- L-8: HSET (field, value) replaces the deprecated HMSET.
redis.call('HSET', key, 'count', count, 'window_start', window_start)
redis.call('EXPIRE', key, window + 1)
local remaining = max - count
return {1, remaining, 0}
`)

// RateLimiter provides Redis-backed per-IP rate limiting.
type RateLimiter struct {
	client      *redis.Client
	maxRequests int
	window      time.Duration
	keyPrefix   string
}

// ParseRate parses "100/min" format into max requests and window.
func ParseRate(rate string) (int, time.Duration, error) {
	parts := strings.SplitN(rate, "/", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid rate format: %q (expected N/period)", rate)
	}

	max, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid rate count: %q", parts[0])
	}

	var window time.Duration
	switch strings.ToLower(parts[1]) {
	case "s", "sec", "second":
		window = time.Second
	case "m", "min", "minute":
		window = time.Minute
	case "h", "hr", "hour":
		window = time.Hour
	default:
		return 0, 0, fmt.Errorf("unknown rate period: %q (use s/m/h)", parts[1])
	}

	return max, window, nil
}

// NewRateLimiter creates a rate limiter with the given config.
func NewRateLimiter(client *redis.Client, maxRequests int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		client:      client,
		maxRequests: maxRequests,
		window:      window,
		keyPrefix:   "ratelimit:",
	}
}

// NewPerUserRateLimiter creates a rate limiter that tracks per-user limits.
func NewPerUserRateLimiter(client *redis.Client, maxRequests int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		client:      client,
		maxRequests: maxRequests,
		window:      window,
		keyPrefix:   "ratelimit:user:",
	}
}

// Middleware returns the rate limit middleware handler.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r)
		if ip == nil {
			writeError(w, http.StatusForbidden, "RATE_LIMIT_ERROR", "unable to determine client IP")
			return
		}

		key := rl.keyPrefix + ip.String()
		now := time.Now().Unix()

		ctx, cancel := context.WithTimeout(r.Context(), 500*time.Millisecond)
		defer cancel()

		result, err := rateLimitScript.Run(ctx, rl.client,
			[]string{key},
			rl.maxRequests,
			int(rl.window.Seconds()),
			now,
		).Int64Slice()

		if err != nil {
			log.Printf("ratelimit: redis error: %v", err)
			writeError(w, http.StatusServiceUnavailable, "RATE_LIMIT_ERROR", "rate limit check failed")
			return
		}

		allowed := result[0]
		remaining := result[1]
		retryAfter := result[2]

		w.Header().Set("X-RateLimit-Limit", strconv.Itoa(rl.maxRequests))
		w.Header().Set("X-RateLimit-Remaining", strconv.FormatInt(remaining, 10))

		if allowed == 0 {
			w.Header().Set("Retry-After", strconv.FormatInt(retryAfter, 10))
			writeError(w, http.StatusTooManyRequests, "RATE_LIMITED",
				fmt.Sprintf("rate limit exceeded, retry in %ds", retryAfter))
			return
		}

		next.ServeHTTP(w, r)
	})
}

// MiddlewarePerUser returns rate limiting middleware that applies limits per authenticated user.
// Requires the auth middleware to have set user claims earlier in the pipeline.
func (rl *RateLimiter) MiddlewarePerUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try to get user ID from context (set by auth middleware)
		userID := ""
		if claims := auth.ClaimsFromContext(r.Context()); claims != nil {
			userID = strconv.Itoa(claims.UserID)
		}

		// Build composite key: user:{id} or ip:{ip} if no user
		var key string
		if userID != "" {
			key = "ratelimit:user:" + userID
		} else {
			ip := extractIP(r)
			if ip != nil {
				key = "ratelimit:ip:" + ip.String()
			} else {
				writeError(w, http.StatusForbidden, "RATE_LIMIT_ERROR", "unable to determine identity")
				return
			}
		}

		now := time.Now().Unix()
		ctx, cancel := context.WithTimeout(r.Context(), 500*time.Millisecond)
		defer cancel()

		result, err := rateLimitScript.Run(ctx, rl.client,
			[]string{key},
			rl.maxRequests,
			int(rl.window.Seconds()),
			now,
		).Int64Slice()

		if err != nil {
			log.Printf("ratelimit: redis error: %v", err)
			writeError(w, http.StatusServiceUnavailable, "RATE_LIMIT_ERROR", "rate limit check failed")
			return
		}

		allowed := result[0]
		remaining := result[1]
		retryAfter := result[2]

		w.Header().Set("X-RateLimit-Limit", strconv.Itoa(rl.maxRequests))
		w.Header().Set("X-RateLimit-Remaining", strconv.FormatInt(remaining, 10))

		if allowed == 0 {
			w.Header().Set("Retry-After", strconv.FormatInt(retryAfter, 10))
			writeError(w, http.StatusTooManyRequests, "RATE_LIMITED",
				fmt.Sprintf("rate limit exceeded, retry in %ds", retryAfter))
			return
		}

		next.ServeHTTP(w, r)
	})
}
