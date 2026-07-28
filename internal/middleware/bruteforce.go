package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/user/waf/internal/ctxutil"
)
// BruteForceProtector tracks login attempts per IP and per IP+username in Redis.
type BruteForceProtector struct {
	rdb            *redis.Client
	maxAttempts    int
	lockDuration   time.Duration
	windowDuration time.Duration
}

// NewBruteForceProtector creates a Redis-backed brute force protector.
func NewBruteForceProtector(rdb *redis.Client, maxAttempts int, lockDuration, windowDuration time.Duration) *BruteForceProtector {
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	if lockDuration <= 0 {
		lockDuration = 15 * time.Minute
	}
	if windowDuration <= 0 {
		windowDuration = 5 * time.Minute
	}
	return &BruteForceProtector{
		rdb:            rdb,
		maxAttempts:    maxAttempts,
		lockDuration:   lockDuration,
		windowDuration: windowDuration,
	}
}

type loginRequestBody struct {
	Username string `json:"username"`
}

// Middleware returns HTTP middleware that blocks brute force login attempts.
func (bp *BruteForceProtector) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := extractIPBF(r)
		if ip == "" {
			next.ServeHTTP(w, r)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 500*time.Millisecond)
		defer cancel()

		// Check IP-level lockout
		lockKey := "bruteforce:lock:" + ip
		locked, ttl, err := bp.isLocked(ctx, lockKey)
		if err != nil {
			log.Printf("bruteforce: redis error: %v", err)
			writeError(w, http.StatusServiceUnavailable, "AUTH_UNAVAILABLE",
				"login temporarily unavailable, try again shortly")
			return
		}
		if locked {
			minutes := int(ttl.Minutes()) + 1
			writeError(w, http.StatusTooManyRequests, "ACCOUNT_LOCKED",
				fmt.Sprintf("too many failed login attempts, locked for %d minutes", minutes))
			return
		}

		// Extract username from request body
		var username string
		bodyBytes, err := ctxutil.ReadOnce(r)
		if err == nil && len(bodyBytes) > 0 {
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			var creds loginRequestBody
			if json.Unmarshal(bodyBytes, &creds) == nil && creds.Username != "" {
				username = creds.Username
			}
		}

		// Check IP attempt count
		attemptsKey := "bruteforce:attempts:" + ip
		ipAttempts, _ := bp.getCount(ctx, attemptsKey)

		if ipAttempts >= bp.maxAttempts {
			bp.setLock(ctx, lockKey)
			bp.deleteKey(ctx, attemptsKey)
			writeError(w, http.StatusTooManyRequests, "ACCOUNT_LOCKED",
				fmt.Sprintf("too many failed attempts, locked for %d minutes", int(bp.lockDuration.Minutes())))
			return
		}

		// Check per-username attempts
		if username != "" {
			userKey := "bruteforce:attempts:" + ip + ":" + username
			userAttempts, _ := bp.getCount(ctx, userKey)
			if userAttempts >= bp.maxAttempts {
				bp.setLock(ctx, lockKey)
				bp.deleteKey(ctx, attemptsKey)
				bp.deleteKey(ctx, userKey)
				writeError(w, http.StatusTooManyRequests, "ACCOUNT_LOCKED",
					fmt.Sprintf("too many failed attempts for this account, locked for %d minutes", int(bp.lockDuration.Minutes())))
				return
			}
		}

		// Wrap response to capture status
		rw := &bruteForceWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)

		// Track failed/succeeded attempts
		if rw.status == http.StatusUnauthorized {
			bp.increment(ctx, attemptsKey)
			if username != "" {
				bp.increment(ctx, "bruteforce:attempts:"+ip+":"+username)
			}
			log.Printf("bruteforce: failed login from %s user=%s", ip, sanitizeLog(username))
		} else if rw.status == http.StatusOK {
			bp.deleteKey(ctx, attemptsKey)
			if username != "" {
				bp.deleteKey(ctx, "bruteforce:attempts:"+ip+":"+username)
			}
		}
	})
}

func (bp *BruteForceProtector) isLocked(ctx context.Context, key string) (bool, time.Duration, error) {
	ttl, err := bp.rdb.TTL(ctx, key).Result()
	if err != nil {
		return false, 0, err
	}
	if ttl == -2 { // key doesn't exist
		return false, 0, nil
	}
	return true, ttl, nil
}

func (bp *BruteForceProtector) getCount(ctx context.Context, key string) (int, error) {
	val, err := bp.rdb.Get(ctx, key).Int()
	if err == redis.Nil {
		return 0, nil
	}
	return val, err
}

func (bp *BruteForceProtector) increment(ctx context.Context, key string) {
	pipe := bp.rdb.Pipeline()
	pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, bp.windowDuration)
	pipe.Exec(ctx)
}

func (bp *BruteForceProtector) setLock(ctx context.Context, key string) {
	bp.rdb.Set(ctx, key, "1", bp.lockDuration)
}

func (bp *BruteForceProtector) deleteKey(ctx context.Context, key string) {
	bp.rdb.Del(ctx, key)
}

func extractIPBF(r *http.Request) string {
	ip := ExtractClientIP(r)
	if ip == nil {
		return ""
	}
	return ip.String()
}

type bruteForceWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (rw *bruteForceWriter) WriteHeader(code int) {
	if !rw.wroteHeader {
		rw.status = code
		rw.wroteHeader = true
	}
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *bruteForceWriter) Write(b []byte) (int, error) {
	if !rw.wroteHeader {
		rw.status = http.StatusOK
		rw.wroteHeader = true
	}
	return rw.ResponseWriter.Write(b)
}
