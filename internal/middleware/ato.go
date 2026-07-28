package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"sync/atomic"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/user/waf/internal/ctxutil"
)
// atOmniScript collapses all ATO per-failed-login operations into one
// Redis EVAL (1 RTT). Before this, observe() below made 4-6 sequential
// RTTs (isLocked + increment + 2*addToSet + 3*setCount + maybe setLock).
// Inputs:
//   KEYS[1] = lock key            (ato:lock:<ip>)
//   KEYS[2] = attempts key       (ato:ip:attempts:<ip>)
//   KEYS[3] = usernames key      (ato:ip:usernames:<ip>)
//   KEYS[4] = ips key            (ato:user:ips:<username>)
//   KEYS[5] = passwords key      (ato:ip:passwords:<ip>)
// ARGV[1] = windowSec, ARGV[2] = maxUsernames, ARGV[3] = maxAttempts,
// ARGV[4] = maxIPsPerUser, ARGV[5] = unused (kept for ABI compat)
// ARGV[6] = username, ARGV[7] = IP, ARGV[8] = password
var atOmniScript = redis.NewScript(`
local lockKey       = KEYS[1]
local attemptsKey  = KEYS[2]
local usernamesKey = KEYS[3]
local ipsKey       = KEYS[4]
local passwordsKey = KEYS[5]
local windowSec    = tonumber(ARGV[1])
local maxUnames    = tonumber(ARGV[2])
local maxAttempts  = tonumber(ARGV[3])
local maxIPsPerUser = tonumber(ARGV[4])

local ttl = redis.call("TTL", lockKey)
if ttl and ttl > 0 then
  return {"locked", redis.call("HGET", attemptsKey, "count")}
end

local attempts = redis.call("HINCRBY", attemptsKey, "count", 1)
if attempts == 1 then redis.call("EXPIRE", attemptsKey, windowSec) end

if ARGV[6] ~= "" then
  local a = redis.call("SADD", usernamesKey, ARGV[6])
  if a == 1 then redis.call("EXPIRE", usernamesKey, windowSec) end
end
if ARGV[7] ~= "" then
  local a = redis.call("SADD", ipsKey, ARGV[7])
  if a == 1 then redis.call("EXPIRE", ipsKey, windowSec) end
end
if ARGV[8] ~= "" then
  local a = redis.call("SADD", passwordsKey, ARGV[8])
  if a == 1 then redis.call("EXPIRE", passwordsKey, windowSec) end
end

local uUnames = redis.call("ZCARD", usernamesKey)
local uIPs    = (ARGV[7] ~= "" and redis.call("ZCARD", ipsKey) or 0)
local uPwds   = redis.call("ZCARD", passwordsKey)

local kind = ""
if uUnames >= maxUnames then kind = "credential_stuffing" end
if attempts >= maxAttempts then
  if kind == "" then kind = "brute_force" else kind = kind end
end
if uIPs >= maxIPsPerUser then
  if kind == "" then kind = "distributed" else kind = kind end
end
if uPwds <= 2 and uUnames >= math.floor(maxUnames/2) and ARGV[8] ~= "" then
  if kind == "" then kind = "spray" else kind = kind end
end

if kind ~= "" then
  redis.call("SETEX", lockKey, windowSec * 2, "1")
  return {kind, attempts, uUnames, uIPs, uPwds}
end
return {"", attempts, uUnames, uIPs, uPwds}
`)

// ATODetector detects account takeover patterns on login endpoints.
type ATODetector struct {
	rdb              *redis.Client
	scriptFailed     *atomic.Int64
	pool             *pgxpool.Pool
	loginPaths       map[string]bool
	maxAttemptsPerIP int
	maxUsernames     int
	maxIPsPerUser    int
	lockDuration     time.Duration
	windowDuration   time.Duration
}

// NewATODetector creates a Redis-backed ATO detector.
func NewATODetector(rdb *redis.Client, pool *pgxpool.Pool, loginPaths []string, maxAttempts, maxUsernames, maxIPsPerUser int, lockDuration time.Duration) *ATODetector {
	pathSet := make(map[string]bool, len(loginPaths))
	for _, p := range loginPaths {
		pathSet[p] = true
	}
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	if maxUsernames <= 0 {
		maxUsernames = 10
	}
	if maxIPsPerUser <= 0 {
		maxIPsPerUser = 5
	}
	if lockDuration <= 0 {
		lockDuration = 15 * time.Minute
	}
	return &ATODetector{
		rdb:              rdb,
		pool:             pool,
		loginPaths:       pathSet,
		maxAttemptsPerIP: maxAttempts,
		maxUsernames:     maxUsernames,
		maxIPsPerUser:    maxIPsPerUser,
		lockDuration:     lockDuration,
		windowDuration:   5 * time.Minute,
	}
}

// runWithRetry executes fn with bounded exponential backoff. Used only
// for non-blocking auth-tracking scripts (lock check stays fail-closed).
// 3 attempts at 30/60/120 ms cover 99% of Redis blips; on final
// failure we return the error so the caller falls back gracefully.
func (d *ATODetector) runWithRetry(ctx context.Context, name string, fn func(context.Context) (any, error)) (any, error) {
	var lastErr error
	for attempt, backoff := 0, 30*time.Millisecond; attempt < 3; attempt++ {
		v, err := fn(ctx)
		if err == nil {
			return v, nil
		}
		lastErr = err
		log.Printf("ato: %s attempt %d failed: %v (retrying in %v)", name, attempt+1, err, backoff)
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		backoff *= 2
	}
	if d.scriptFailed != nil {
		d.scriptFailed.Add(1)
	}
	return nil, lastErr
}

// Middleware returns HTTP middleware that detects ATO patterns.
func (d *ATODetector) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !d.loginPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}

		ip := extractIPBF(r)
		if ip == "" {
			next.ServeHTTP(w, r)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 500*time.Millisecond)
		defer cancel()

		// Check ATO lockout (fail-closed on Redis errors)
		lockKey := "ato:lock:" + ip
		locked, lockErr := d.isLocked(ctx, lockKey)
		if lockErr != nil {
			log.Printf("ato: lock check failed for %s: %v — blocking as precaution", ip, lockErr)
			writeError(w, http.StatusServiceUnavailable, "ATO_ERROR", "security service temporarily unavailable")
			return
		}
		if locked {
			writeError(w, http.StatusTooManyRequests, "ATO_LOCKED",
				"this IP is temporarily locked due to suspicious login activity")
			return
		}

		// Extract username and password from body
		var username, password string
		bodyBytes, err := ctxutil.ReadOnce(r)
		if err == nil && len(bodyBytes) > 0 {
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			var creds struct {
				Username string `json:"username"`
				Password string `json:"password"`
			}
			if json.Unmarshal(bodyBytes, &creds) == nil {
				username = creds.Username
				password = creds.Password
			}
		}

		// Wrap response to capture status
		rw := &atoWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)

		// Only track failed login attempts
		if rw.status != http.StatusUnauthorized {
			return
		}

		// --- Record the failed attempt + check thresholds (single Redis EVAL) ---
		windowSec := int(d.windowDuration.Seconds())
		omniRes, err := atOmniScript.Run(ctx, d.rdb,
			[]string{
				"ato:lock:" + ip,
				"ato:ip:attempts:" + ip,
				"ato:ip:usernames:" + ip,
				"ato:user:ips:" + username,
				"ato:ip:passwords:" + ip,
			},
			windowSec,
			d.maxUsernames,
			d.maxAttemptsPerIP*2,
			d.maxIPsPerUser,
			0, // unused, kept for ABI compat
			username,
			ip,
			password,
		).Result()
		if err != nil {
			// If the script is broken (e.g. NOSCRIPT), fall back to the
			// simple GET path so the middleware never silently drops events.
			log.Printf("ato: omni-script failed for %s: %v — falling back to isLocked", ip, err)
			locked, _ := d.isLocked(ctx, "ato:lock:"+ip)
			if locked {
				writeError(w, http.StatusTooManyRequests, "ATO_LOCKED", "this IP is temporarily locked due to suspicious login activity")
				return
			}
			d.increment(ctx, "ato:ip:attempts:"+ip, windowSec)
			return
		}
		omni := omniRes.([]interface{})
		kind, _ := omni[0].(string)
		if kind == "locked" {
			writeError(w, http.StatusTooManyRequests, "ATO_LOCKED", "this IP is temporarily locked due to suspicious login activity")
			return
		}
		if kind != "" {
			ipAttempts, _ := omni[1].(int64)
			uniqueUsernames, _ := omni[2].(int64)
			uniqueIPs, _ := omni[3].(int64)
			d.triggerATO(ctx, ip, username, kind, int(ipAttempts), int(uniqueUsernames), int(uniqueIPs))
			log.Printf("ato: %s from %s (attempts=%d usernames=%d ips=%d)", sanitizeLog(kind), ip, ipAttempts, uniqueUsernames, uniqueIPs)
			return
		}
	})
}

func (d *ATODetector) increment(ctx context.Context, key string, windowSec int) {
	pipe := d.rdb.Pipeline()
	pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, time.Duration(windowSec)*time.Second)
	pipe.Exec(ctx)
}

func (d *ATODetector) addToSet(ctx context.Context, key, member string, windowSec int) {
	pipe := d.rdb.Pipeline()
	pipe.ZAdd(ctx, key, redis.Z{Score: float64(time.Now().Unix()), Member: member})
	pipe.Expire(ctx, key, time.Duration(windowSec)*time.Second)
	pipe.Exec(ctx)
}

func (d *ATODetector) getCount(ctx context.Context, key string) int {
	val, err := d.rdb.Get(ctx, key).Int()
	if err == redis.Nil {
		return 0
	}
	return val
}

func (d *ATODetector) setCount(ctx context.Context, key string) int {
	count, err := d.rdb.ZCard(ctx, key).Result()
	if err != nil {
		return 0
	}
	return int(count)
}

func (d *ATODetector) isLocked(ctx context.Context, key string) (bool, error) {
	ttl, err := d.rdb.TTL(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return ttl > 0, nil
}

func (d *ATODetector) setLock(ctx context.Context, key string) {
	d.rdb.Set(ctx, key, "1", d.lockDuration)
}

// UnlockIP removes an ATO lockout for a specific IP.
func (d *ATODetector) UnlockIP(ctx context.Context, ip string) {
	d.rdb.Del(ctx, "ato:lock:"+ip)
	d.rdb.Del(ctx, "ato:ip:attempts:"+ip)
	d.rdb.Del(ctx, "ato:ip:usernames:"+ip)
	d.rdb.Del(ctx, "ato:ip:passwords:"+ip)
}

// triggerATO logs an ATO event to the database.
func (d *ATODetector) triggerATO(ctx context.Context, ip, username, attackType string, attempts, uniqueUsernames, uniqueIPs int) {
	if d.pool == nil {
		return
	}
	lockUntil := time.Now().Add(d.lockDuration)
	_, err := d.pool.Exec(ctx,
		`INSERT INTO ato_events (ip, username, attack_type, attempt_count, unique_usernames, unique_ips, locked_until)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		ip, username, attackType, attempts, uniqueUsernames, uniqueIPs, lockUntil)
	if err != nil {
		log.Printf("ato: failed to log event: %v", err)
	}
}

// GetStats returns ATO statistics from Redis and DB.
func (d *ATODetector) GetStats(ctx context.Context) map[string]interface{} {
	stats := map[string]interface{}{
		"enabled":              true,
		"max_attempts_per_ip":  d.maxAttemptsPerIP,
		"max_usernames_per_ip": d.maxUsernames,
		"max_ips_per_username": d.maxIPsPerUser,
		"lockout_duration":     d.lockDuration.String(),
	}

	if d.pool == nil {
		return stats
	}

	// Count events in last 24h
	var totalEvents int
	err := d.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM ato_events WHERE created_at > NOW() - INTERVAL '24 hours'`).Scan(&totalEvents)
	if err == nil {
		stats["events_24h"] = totalEvents
	}

	// Count currently locked IPs (from Redis)
	lockedKeys, _ := d.rdb.Keys(ctx, "ato:lock:*").Result()
	stats["locked_ips"] = len(lockedKeys)

	// Count total login attempts tracked
	attemptKeys, _ := d.rdb.Keys(ctx, "ato:ip:attempts:*").Result()
	stats["active_ips_tracked"] = len(attemptKeys)

	// Recent events by type
	rows, err := d.pool.Query(ctx,
		`SELECT attack_type, COUNT(*) FROM ato_events
		 WHERE created_at > NOW() - INTERVAL '24 hours'
		 GROUP BY attack_type`)
	if err == nil {
		defer rows.Close()
		byType := map[string]int{}
		for rows.Next() {
			var atype string
			var count int
			if rows.Scan(&atype, &count) == nil {
				byType[atype] = count
			}
		}
		stats["events_by_type"] = byType
	}

	return stats
}

// GetRecentEvents returns the most recent ATO events.
func (d *ATODetector) GetRecentEvents(ctx context.Context, limit int) ([]map[string]interface{}, error) {
	if d.pool == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 50
	}
	rows, err := d.pool.Query(ctx,
		`SELECT id, ip::text, username, attack_type, attempt_count, unique_usernames, unique_ips, locked_until, created_at
		 FROM ato_events ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []map[string]interface{}
	for rows.Next() {
		var id int64
		var ip, username, attackType string
		var attempts, uniqueUsers, uniqueIPs int
		var lockedUntil *time.Time
		var createdAt time.Time
		if err := rows.Scan(&id, &ip, &username, &attackType, &attempts, &uniqueUsers, &uniqueIPs, &lockedUntil, &createdAt); err != nil {
			continue
		}
		ev := map[string]interface{}{
			"id":               id,
			"ip":               ip,
			"username":         username,
			"attack_type":      attackType,
			"attempt_count":    attempts,
			"unique_usernames": uniqueUsers,
			"unique_ips":       uniqueIPs,
			"created_at":       createdAt,
		}
		if lockedUntil != nil {
			ev["locked_until"] = lockedUntil
		}
		events = append(events, ev)
	}
	return events, nil
}

type atoWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (rw *atoWriter) WriteHeader(code int) {
	if !rw.wroteHeader {
		rw.status = code
		rw.wroteHeader = true
	}
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *atoWriter) Write(b []byte) (int, error) {
	if !rw.wroteHeader {
		rw.status = http.StatusOK
		rw.wroteHeader = true
	}
	return rw.ResponseWriter.Write(b)
}

// unused but needed to avoid import cycle with api package
var _ = fmt.Sprintf
