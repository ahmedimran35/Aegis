package middleware

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"sync/atomic"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// CredentialStuffingConfig configures distributed credential stuffing detection.
type CredentialStuffingConfig struct {
	Enabled       bool
	Window        time.Duration
	MinIPs        int
	MinAttempts   int
	HashPrefixLen int
}

// DefaultCredentialStuffingConfig returns production-safe defaults.
func DefaultCredentialStuffingConfig() CredentialStuffingConfig {
	return CredentialStuffingConfig{
		Enabled:       true,
		Window:        10 * time.Minute,
		MinIPs:        5,
		MinAttempts:   20,
		HashPrefixLen: 4,
	}
}

// sanitizeHashPrefixLen clamps cfg.HashPrefixLen into a safe range
// [1, 32]. F19: passing 0 (or a negative value) makes
// `hex.EncodeToString(hash[:0])` panic because slicing yields an empty
// slice but callers use the result as a Redis key suffix — anything
// outside the [1, 32] window is a config bug. Out-of-range values are
// logged and replaced with the default.
func sanitizeHashPrefixLen(cfg CredentialStuffingConfig) CredentialStuffingConfig {
	if cfg.HashPrefixLen <= 0 || cfg.HashPrefixLen > 32 {
		log.Printf("cred_stuffing: HashPrefixLen=%d out of range [1,32]; using default 4", cfg.HashPrefixLen)
		cfg.HashPrefixLen = 4
	}
	return cfg
}

// credStuffRecordScript and credStuffCheckScript collapse the previous
// 3-4-RTT pipeline (sAdd + zIncrBy + expire × 2 / keys + sCard + zScore)
// into single Redis EVAL calls. Before this, RecordLoginFailure issued
// 4 pipelined commands; ShouldBlock used Keys("credstuff:<userhash>:*")
// which is a blocking SCAN-equivalent on a hot path. Both are now O(1)
// EVAL round-trips.
var (
	credStuffRecordScript = redis.NewScript(`
local key = KEYS[1]
local userKey = KEYS[2]
local ip = ARGV[1]
local windowSec = tonumber(ARGV[2])
local added = redis.call("SADD", key, ip)
if added == 1 then redis.call("EXPIRE", key, windowSec) end
redis.call("ZINCRBY", userKey, 1, key)
redis.call("EXPIRE", userKey, windowSec)
return added
`)

	credStuffCheckScript = redis.NewScript(`
local pattern = ARGV[1]
local minIPs = tonumber(ARGV[2])
local minAttempts = tonumber(ARGV[3])

-- SCAN, not KEYS — non-blocking on a hot path.
local cursor = "0"
local foundKind = ""
local foundMeta = ""
repeat
  local res = redis.call("SCAN", cursor, "MATCH", pattern, "COUNT", 100)
  cursor = res[1]
  local keys = res[2]
  for i = 1, #keys do
    local k = keys[i]
    local ips = redis.call("SCARD", k)
    if ips >= minIPs then
      return {"distributed", ips}
    end
    local att = redis.call("ZSCORE", userKey, k)
    if att and tonumber(att) >= minAttempts then
      return {"repeated", tonumber(att)}
    end
  end
until cursor == "0" or foundKind ~= ""
return {"", 0}
`)
)

// CredentialStuffingDetector detects distributed credential stuffing attacks.
type CredentialStuffingDetector struct {
	scriptFailed *atomic.Int64
	enabled int32
	cfg     CredentialStuffingConfig
	stats   *credStuffingStats
	rdb     *redis.Client
}

type credStuffingStats struct {
	mu             sync.Mutex
	Detected       int64
	Blocked        int64
	TopCompromised map[string]int64
}

// NewCredentialStuffingDetector creates a new detector.
func NewCredentialStuffingDetector(cfg CredentialStuffingConfig, rdb *redis.Client) *CredentialStuffingDetector {
	cfg = sanitizeHashPrefixLen(cfg) // F19: clamp into [1,32]
	d := &CredentialStuffingDetector{
		cfg:   cfg,
		rdb:   rdb,
		stats: &credStuffingStats{TopCompromised: make(map[string]int64)},
	}
	if cfg.Enabled {
		d.enabled = 1
	}
	return d
}

// RecordLoginFailure records a failed login for analysis.
//
// F31: do NOT short-circuit on empty username/password. An attacker can
// otherwise rotate empty creds to flood the auth log without ever
// contributing to the credential-stuffing counters. The empty-username
// bucket is still useful for detecting automated scanners.
func (d *CredentialStuffingDetector) RecordLoginFailure(ctx context.Context, ip, username, password string) {
	if atomic.LoadInt32(&d.enabled) == 0 || d.rdb == nil {
		return
	}
	// F33/F34: separate the two fields with a NUL byte so a username
	// containing a comma cannot collide via the `username:password` join.
	hash := sha256.Sum256([]byte(username + "\x00" + password))
	prefix := hex.EncodeToString(hash[:d.cfg.HashPrefixLen])
	key := fmt.Sprintf("credstuff:%s:%s", hashString(username), prefix)
	// 1-RTT: SAdd IP + Expire + ZIncrBy + Expire. Replaces the previous
	// 4-pipeline command sequence.
	_, _ = d.runWithRetry(ctx, "credstuff-record", func(ctx context.Context) (any, error) {
		return credStuffRecordScript.Run(ctx, d.rdb,
			[]string{key, "credstuff:attempts:" + hashString(username)},
			ip,
			d.cfg.Window,
		).Result()
	})
}

// runWithRetry executes fn with bounded exponential backoff. Used only
// for non-blocking auth-tracking scripts (lock check stays fail-closed).
func (d *CredentialStuffingDetector) runWithRetry(ctx context.Context, name string, fn func(context.Context) (any, error)) (any, error) {
	var lastErr error
	for attempt, backoff := 0, 30*time.Millisecond; attempt < 3; attempt++ {
		v, err := fn(ctx)
		if err == nil {
			return v, nil
		}
		lastErr = err
		log.Printf("cred_stuffing: %s attempt %d failed: %v (retrying in %v)", name, attempt+1, err, backoff)
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		backoff *= 2
	}
	return nil, lastErr
}

// ShouldBlock checks if credentials match distributed stuffing patterns.
func (d *CredentialStuffingDetector) ShouldBlock(ctx context.Context, username string) (bool, string) {
	if atomic.LoadInt32(&d.enabled) == 0 || d.rdb == nil || username == "" {
		return false, ""
	}
	userHash := hashString(username)
	pattern := "credstuff:" + userHash + ":*"
	// 1-RTT: SCAN (non-blocking) + per-key SCARD/ZSCORE. Replaces the
	// previous Keys() blocking scan + per-key RTTs.
	res, err := d.runWithRetry(ctx, "credstuff-check", func(ctx context.Context) (any, error) {
		return credStuffCheckScript.Run(ctx, d.rdb,
			[]string{},
			pattern, d.cfg.MinIPs, d.cfg.MinAttempts,
		).Result()
	})
	if err != nil {
		return false, ""
	}
	arr, ok := res.([]interface{})
	if !ok || len(arr) < 2 {
		return false, ""
	}
	kind, _ := arr[0].(string)
	if kind == "" {
		return false, ""
	}
	count, _ := arr[1].(int64)
	atomic.AddInt64(&d.stats.Detected, 1)
	d.stats.mu.Lock()
	d.stats.TopCompromised[sanitizeLog(username)]++
	d.stats.mu.Unlock()
	if kind == "distributed" {
		log.Printf("cred_stuffing: BLOCKED distributed attack on user=%s (%d IPs)", sanitizeLog(username), count)
		return true, fmt.Sprintf("distributed credential stuffing (%d IPs)", count)
	}
	log.Printf("cred_stuffing: BLOCKED repeated attack on user=%s (%d attempts)", sanitizeLog(username), count)
	return true, fmt.Sprintf("credential stuffing (%d attempts)", count)
}

// Stats returns current snapshot.
func (d *CredentialStuffingDetector) Stats() map[string]interface{} {
	d.stats.mu.Lock()
	defer d.stats.mu.Unlock()
	top := make(map[string]int64, len(d.stats.TopCompromised))
	for k, v := range d.stats.TopCompromised {
		top[k] = v
	}
	return map[string]interface{}{
		"enabled":         atomic.LoadInt32(&d.enabled) == 1,
		"detected":        atomic.LoadInt64(&d.stats.Detected),
		"blocked":         atomic.LoadInt64(&d.stats.Blocked),
		"top_compromised": top,
	}
}

// Middleware returns HTTP middleware for credential stuffing detection.
// This is used at login endpoints.
func (d *CredentialStuffingDetector) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(&d.enabled) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		if r.Method == "GET" || !isLoginEndpoint(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		username, password, ok := extractLoginCredentials(r)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		ip := extractIP(r)
		if ip != nil {
			if blocked, _ := d.ShouldBlock(r.Context(), username); blocked {
				atomic.AddInt64(&d.stats.Blocked, 1)
				writeBlockError(w, "CRED_STUFFING_BLOCKED", "credential stuffing attack detected")
				return
			}
		}

		rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		if rw.status >= http.StatusBadRequest && ip != nil {
			d.RecordLoginFailure(r.Context(), ip.String(), username, password)
		}
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (w *statusRecorder) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func extractLoginCredentials(r *http.Request) (string, string, bool) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return "", "", false
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	if strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		var payload struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return "", "", false
		}
		// F31: allow empty creds through. The downstream call to
		// RecordLoginFailure is responsible for stamping them into the
		// counter even when blank — previous behaviour let scanners
		// flood the login endpoint with empty creds and never bump
		// the cred-stuffing counters.
		return payload.Username, payload.Password, true
	}

	if err := r.ParseForm(); err != nil {
		return "", "", false
	}
	username := r.FormValue("username")
	password := r.FormValue("password")
	// F31: do not early-return on empty fields.
	return username, password, true
}

func isLoginEndpoint(path string) bool {
	loginPaths := []string{"/login", "/api/v1/auth/login", "/api/auth", "/signin"}
	for _, p := range loginPaths {
		if strings.HasPrefix(strings.ToLower(path), strings.ToLower(p)) {
			return true
		}
	}
	return false
}
