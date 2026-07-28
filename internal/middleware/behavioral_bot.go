package middleware

import (
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/redis/go-redis/v9"
	"github.com/user/waf/internal/util/lru"
)

// BehavioralBotConfig holds configuration for behavioral bot detection.
type BehavioralBotConfig struct {
	Enabled        bool
	ScoreThreshold int
	Action         string
}

// H-8: hard cap on the TopBotTypes LRU.
const defaultBehavioralBotTopTypes = 10000

// DefaultBehavioralBotConfig returns production-safe defaults.
func DefaultBehavioralBotConfig() BehavioralBotConfig {
	return BehavioralBotConfig{
		Enabled:        true,
		ScoreThreshold: 5,
		Action:         "challenge",
	}
}

// BehavioralBotScorer scores requests based on behavioral signals.
type BehavioralBotScorer struct {
	enabled int32
	cfg     BehavioralBotConfig
	stats   *behavioralBotStats
	rdb     *redis.Client
}

type behavioralBotStats struct {
	mu           sync.Mutex
	TotalChecked int64
	Blocked      int64
	Challenged   int64
	Suspicious   int64
	Allowed      int64
	// H-8: bounded LRU map replaces the previous unbounded map.
	topBotTypes *lru.LRU[string, int64]
}

// BehavioralBotStatsSnapshot is the public stats snapshot.
type BehavioralBotStatsSnapshot struct {
	Enabled         bool             `json:"enabled"`
	TotalChecked    int64            `json:"total_checked"`
	Blocked         int64            `json:"blocked"`
	Challenged      int64            `json:"challenged"`
	Suspicious      int64            `json:"suspicious"`
	Allowed         int64            `json:"allowed"`
	ScoreThreshold  int              `json:"score_threshold"`
	Mode            string           `json:"mode"`
	TopBotTypes     map[string]int64 `json:"top_bot_types"`
}

// NewBehavioralBotScorer creates a new behavioral bot scorer.
func NewBehavioralBotScorer(cfg BehavioralBotConfig, rdb *redis.Client) *BehavioralBotScorer {
	s := &BehavioralBotScorer{
		cfg: cfg,
		rdb: rdb,
		stats: &behavioralBotStats{
			topBotTypes: lru.New[string, int64](defaultBehavioralBotTopTypes),
		},
	}
	if cfg.Enabled {
		s.enabled = 1
	}
	return s
}

// Middleware returns HTTP middleware that scores requests behaviorally.
func (s *BehavioralBotScorer) Middleware(next http.Handler) http.Handler {
	if atomic.LoadInt32(&s.enabled) == 0 {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		score := s.scoreRequest(r)
		action := s.decide(score)

		switch action {
		case "block":
			atomic.AddInt64(&s.stats.Blocked, 1)
			log.Printf("behavioral_bot: BLOCKED score=%d ip=%s", score, sanitizeLog(extractIP(r).String()))
			writeBlockError(w, "BOT_BLOCKED", "bot detection triggered")
			return
		case "challenge":
			atomic.AddInt64(&s.stats.Challenged, 1)
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"BOT_CHALLENGE_REQUIRED","message":"additional verification"}`))
			return
		case "suspicious":
			atomic.AddInt64(&s.stats.Suspicious, 1)
			if m := MetricsFromContext(r.Context()); m != nil {
				m.AIClassification = "suspicious"
			}
		default:
			atomic.AddInt64(&s.stats.Allowed, 1)
		}

		atomic.AddInt64(&s.stats.TotalChecked, 1)
		next.ServeHTTP(w, r)
	})
}

func (s *BehavioralBotScorer) scoreRequest(r *http.Request) int {
	score := 0
	ua := strings.ToLower(r.UserAgent())

	if ua == "" || len(ua) < 5 {
		score += 2
	}
	if r.Header.Get("Accept") == "" {
		score += 1
	}
	if r.Header.Get("Accept-Language") == "" && ua != "" {
		score += 1
	}
	if r.Header.Get("Sec-Fetch-Site") == "" && ua != "" {
		score += 1
	}
	if len(r.Header) < 5 && ua != "" {
		score += 2
	}
	return score
}

func (s *BehavioralBotScorer) decide(score int) string {
	if score >= s.cfg.ScoreThreshold+4 {
		return "block"
	}
	if score >= s.cfg.ScoreThreshold+2 {
		return "challenge"
	}
	if score >= s.cfg.ScoreThreshold {
		return "suspicious"
	}
	return "allow"
}

// Stats returns a snapshot.
func (s *BehavioralBotScorer) Stats() BehavioralBotStatsSnapshot {
	top := s.stats.topBotTypes.Snapshot()
	return BehavioralBotStatsSnapshot{
		Enabled:        atomic.LoadInt32(&s.enabled) == 1,
		TotalChecked:   atomic.LoadInt64(&s.stats.TotalChecked),
		Blocked:        atomic.LoadInt64(&s.stats.Blocked),
		Challenged:     atomic.LoadInt64(&s.stats.Challenged),
		Suspicious:     atomic.LoadInt64(&s.stats.Suspicious),
		Allowed:        atomic.LoadInt64(&s.stats.Allowed),
		ScoreThreshold: s.cfg.ScoreThreshold,
		Mode:           s.cfg.Action,
		TopBotTypes:    top,
	}
}