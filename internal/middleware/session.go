package middleware

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// SessionTracker tracks client sessions via cookies + Redis + Postgres.
type SessionTracker struct {
	pool       *pgxpool.Pool
	client     *redis.Client
	cookieName string
	ttl        time.Duration
	enabled    bool
	// Bounded in-memory cache for Redis EXISTS checks. Capped at
	// maxSessionCache entries to bound memory regardless of unique
	// session count. Each entry expires after sessionCacheTTL — long
	// enough to absorb burst auth, short enough to invalidate a
	// banned session promptly.
	cache        map[string]sessionCacheEntry
	cacheTTL     time.Duration
	cacheMax     int
	cacheCursor  int // simple LRU eviction cursor (FIFO is fine for 10s TTL)
}
type sessionCacheEntry struct {
	valid   bool
	expires time.Time
}

// NewSessionTracker creates a session tracker.
func NewSessionTracker(pool *pgxpool.Pool, client *redis.Client, cookieName string, ttl time.Duration, enabled bool) *SessionTracker {
	return &SessionTracker{
		pool:       pool,
		client:     client,
		cookieName: cookieName,
		ttl:        ttl,
		enabled:    enabled,
		// TTL cap: 10s. Cache size cap: 4096. Bounded by request rate ×
		// 10s; for a server doing 1k RPS, that's at most 10k active
		// sessions in the window. We round-robin evict when full.
		cache:       make(map[string]sessionCacheEntry, 256),
		cacheTTL:    10 * time.Second,
		cacheMax:    4096,
	}
}

// cacheSessionLookup records a hit in the in-memory cache. FIFO eviction
// when cacheMax is reached. The cache is a memory bound — not a security
// control — the real authoritative check is always the Redis EXISTS.
func (st *SessionTracker) cacheSessionLookup(id string, valid bool) {
	if !st.enabled {
		return
	}
	if len(st.cache) >= st.cacheMax {
		// Cheap eviction: drop any expired entry; otherwise oldest by
		// scan (bounded work — small map).
		now := time.Now()
		for k, v := range st.cache {
			if !v.expires.After(now) || st.cacheCursor > 0 {
				delete(st.cache, k)
				if st.cacheCursor > 0 {
					st.cacheCursor--
				}
			}
		}
	}
	st.cache[id] = sessionCacheEntry{valid: valid, expires: time.Now().Add(st.cacheTTL)}
}

func (st *SessionTracker) fingerprint(r *http.Request) string {
	ua := r.UserAgent()
	accept := r.Header.Get("Accept-Language")
	enc := r.Header.Get("Accept-Encoding")
	acceptCharset := r.Header.Get("Accept-Charset")
	cacheControl := r.Header.Get("Cache-Control")
	conn := r.Header.Get("Connection")
	h := sha256.Sum256([]byte(ua + "|" + accept + "|" + enc + "|" + acceptCharset + "|" + cacheControl + "|" + conn))
	return hex.EncodeToString(h[:16])
}

// Middleware returns the session tracking middleware.
func (st *SessionTracker) Middleware(next http.Handler) http.Handler {
	if !st.enabled {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r)
		ipStr := ""
		if ip != nil {
			ipStr = ip.String()
		}

		cookie, err := r.Cookie(st.cookieName)
		sessionID := ""
		if err == nil {
			sessionID = cookie.Value
		}

		// Validate session exists in Redis to prevent fixation attacks.
		// Bounded LRU cache absorbs the hot path: hot sessions cost 0 RTTs
		// for cacheTTL (10s) per entry; cold or banned sessions fall through
		// to Redis. The cache is memory-bounded and is NOT the security
		// boundary — the authoritative check is always the Redis EXISTS.
		if sessionID != "" {
			if st.enabled {
				if entry, ok := st.cache[sessionID]; ok && entry.expires.After(time.Now()) {
					if !entry.valid {
						sessionID = ""
					}
				} else {
					ctx := context.Background()
					exists, redisErr := st.client.Exists(ctx, "session:"+sessionID).Result()
					st.cacheSessionLookup(sessionID, redisErr == nil && exists == 1)
					if redisErr != nil || exists == 0 {
						sessionID = ""
					}
				}
			} else {
				ctx := context.Background()
				exists, redisErr := st.client.Exists(ctx, "session:"+sessionID).Result()
				if redisErr != nil || exists == 0 {
					sessionID = ""
				}
			}
		}

		fp := st.fingerprint(r)
		now := time.Now().UTC()
		nowStr := now.Format(time.RFC3339)

		// Auto-detect HTTPS: direct TLS or behind reverse proxy.
		// P-FIX (M-58): we only honor X-Forwarded-Proto when the request
		// arrived from a configured trusted proxy. Otherwise an attacker
		// can spoof the header and make the browser treat the session
		// cookie as Secure without TLS behind it (CWE-614/CWE-870).
		isSecure := r.TLS != nil || (r.Header.Get("X-Forwarded-Proto") == "https" && IsTrustedProxyReq(r))

		isNew := false
		if sessionID == "" {
			b := make([]byte, 32)
			if _, err := rand.Read(b); err != nil {
				log.Printf("session: generate id: %v", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			sessionID = hex.EncodeToString(b)
			isNew = true

			sameSite := http.SameSiteLaxMode
			if isSecure {
				sameSite = http.SameSiteStrictMode
			}

			http.SetCookie(w, &http.Cookie{
				Name:     st.cookieName,
				Value:    sessionID,
				Path:     "/",
				HttpOnly: true,
				Secure:   isSecure,
				SameSite: sameSite,
				MaxAge:   int(st.ttl.Seconds()),
			})
		}

		ctx := context.Background()

		// Redis: fast lookup
		key := "session:" + sessionID
		st.client.HSet(ctx, key, map[string]interface{}{
			"ip":        ipStr,
			"ua":        r.UserAgent(),
			"fp":        fp,
			"last_seen": nowStr,
		})
		st.client.HIncrBy(ctx, key, "reqs", 1)
		st.client.Expire(ctx, key, st.ttl)

		fpKey := "session_fp:" + fp
		st.client.SAdd(ctx, fpKey, sessionID)
		st.client.Expire(ctx, fpKey, st.ttl)

		// Postgres: persistent storage (upsert)
		if isNew {
			go st.upsertSession(sessionID, ipStr, r.UserAgent(), fp, now)
		} else {
			go st.updateSession(sessionID, now)
		}

		reqCtx := context.WithValue(r.Context(), sessionIDKey, sessionID)
		next.ServeHTTP(w, r.WithContext(reqCtx))

		// After response, check if blocked
		if rw, ok := w.(*responseWriter); ok && rw.statusCode >= 400 {
			st.client.HIncrBy(ctx, key, "blocked", 1)
			go st.incrementBlocked(sessionID)
		}
	})
}

func (st *SessionTracker) upsertSession(id, ip, ua, fp string, now time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := st.pool.Exec(ctx,
		`INSERT INTO sessions (id, client_ip, user_agent, fingerprint, first_seen, last_seen, request_count, blocked_count)
		 VALUES ($1, $2, $3, $4, $5, $5, 1, 0)
		 ON CONFLICT (id) DO UPDATE SET
		   last_seen = EXCLUDED.last_seen,
		   request_count = sessions.request_count + 1`,
		id, ip, ua, fp, now)
	if err != nil {
		log.Printf("session: upsert: %v", err)
	}
}

func (st *SessionTracker) updateSession(id string, now time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := st.pool.Exec(ctx,
		`UPDATE sessions SET last_seen = $1, request_count = request_count + 1 WHERE id = $2`,
		now, id)
	if err != nil {
		log.Printf("session: update: %v", err)
	}
}

func (st *SessionTracker) incrementBlocked(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := st.pool.Exec(ctx,
		`UPDATE sessions SET blocked_count = blocked_count + 1 WHERE id = $1`, id)
	if err != nil {
		log.Printf("session: increment blocked: %v", err)
	}
}

type ctxKey string

const sessionIDKey ctxKey = "session_id"

// SessionIDFromContext extracts session ID from context.
func SessionIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(sessionIDKey).(string)
	return v
}

// GetFingerprint retrieves the fingerprint for a session ID from Redis.
func (st *SessionTracker) GetFingerprint(ctx context.Context, sessionID string) (string, error) {
	if !st.enabled {
		return "", nil
	}
	key := "session:" + sessionID
	fp, err := st.client.HGet(ctx, key, "fp").Result()
	if err == redis.Nil {
		return "", nil
	}
	return fp, err
}

// Stop is a no-op for session tracker.
func (st *SessionTracker) Stop() {}
