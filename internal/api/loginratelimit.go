package api

import (
	"log"
	"net/http"
	"sync"
	"time"

	wafmw "github.com/user/waf/internal/middleware"
)

type loginAttempt struct {
	mu        sync.Mutex
	count     int
	windowEnd time.Time
}

// LoginRateLimiter limits login attempts per IP.
type LoginRateLimiter struct {
	attempts sync.Map
	max      int
	window   time.Duration

	// H-10: lifecycle for the cleanup goroutine.
	stopCh chan struct{}
	doneCh chan struct{}
	once   sync.Once
}

// NewLoginRateLimiter creates a rate limiter for login endpoints.
func NewLoginRateLimiter(maxAttempts int, window time.Duration) *LoginRateLimiter {
	rl := &LoginRateLimiter{
		max:    maxAttempts,
		window: window,
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
	go rl.cleanup()
	return rl
}

// Stop terminates the cleanup goroutine. Safe to call multiple times.
func (rl *LoginRateLimiter) Stop() {
	rl.once.Do(func() {
		close(rl.stopCh)
		<-rl.doneCh
	})
}

// Middleware returns an HTTP handler that rate-limits by client IP.
func (rl *LoginRateLimiter) Middleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ipObj := wafmw.ExtractClientIP(r)
		if ipObj == nil {
			next.ServeHTTP(w, r)
			return
		}
		ip := ipObj.String()

		val, _ := rl.attempts.LoadOrStore(ip, &loginAttempt{})
		attempt := val.(*loginAttempt)

		attempt.mu.Lock()
		if time.Now().After(attempt.windowEnd) {
			attempt.count = 0
			attempt.windowEnd = time.Now().Add(rl.window)
		}
		attempt.count++
		exceeded := attempt.count > rl.max
		attempt.mu.Unlock()

		if exceeded {
			RespondError(w, http.StatusTooManyRequests, "RATE_LIMITED", "too many login attempts, try again later")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (rl *LoginRateLimiter) cleanup() {
	defer close(rl.doneCh)
	defer func() {
		if r := recover(); r != nil {
			// H-10: a panic in cleanup must not kill the process; the
			// next tick will retry from a clean state.
			log.Printf("loginratelimit: cleanup panic recovered: %v", r)
		}
	}()
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-rl.stopCh:
			return
		case <-ticker.C:
			rl.attempts.Range(func(key, value interface{}) bool {
				attempt := value.(*loginAttempt)
				attempt.mu.Lock()
				expired := time.Now().After(attempt.windowEnd)
				attempt.mu.Unlock()
				if expired {
					rl.attempts.Delete(key)
				}
				return true
			})
		}
	}
}

