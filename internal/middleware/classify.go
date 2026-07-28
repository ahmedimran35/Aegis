package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/user/waf/internal/ai"
	"github.com/user/waf/internal/config"
)

// AIClassifyMiddleware uses AI to classify requests for threats.
func AIClassifyMiddleware(router *ai.Router, rdb *redis.Client, cfg *config.AIClassifyConfig) Middleware {
	if cfg == nil {
		cfg = &config.AIClassifyConfig{
			FailClosed:      false,
			FailClosedPaths: []string{"/api/v1/auth/", "/admin", "/wp-admin", "/phpmyadmin"},
			Timeout:         10 * time.Second,
		}
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := extractIP(r)
			ipStr := ""
			if ip != nil {
				ipStr = ip.String()
			}

			// Read body for AI classification
			body := readBody(r)
			bodySnippet := ""
			if len(body) > 500 {
				bodySnippet = body[:500]
			} else {
				bodySnippet = body
			}

			features := ai.RequestFeatures{
				Method:      r.Method,
				Path:        r.URL.Path,
				QueryParams: r.URL.RawQuery,
				ContentType: r.Header.Get("Content-Type"),
				UserAgent:   r.UserAgent(),
				BodyHash:    hashString(body),
				BodySnippet: bodySnippet,
				ClientIP:    ipStr,
				HeaderCount: len(r.Header),
				ParamCount:  len(r.URL.Query()),
			}

			// F48: cache key uses ONLY canonicalized features (method,
			// path, normalized body hash). Including raw query params
			// allows an attacker to generate unbounded unique cache
			// entries by appending random garbage to the query string
			// — a classic cache-flooding DoS. The QueryParams value is
			// still passed to the AI in `features` for classification,
			// but it does not influence the cache key.
			cacheKey := "ai:cache:" + ipStr + ":" + canonicalRequestHash(features)
			ctx := r.Context()

			cached, err := rdb.Get(ctx, cacheKey).Result()
			if err == nil && cached != "" {
				// Cache hit — store in metrics. Format: "classification" or "classification:score"
				classification := cached
				var cachedScore float64
				if idx := strings.Index(cached, ":"); idx > 0 {
					classification = cached[:idx]
					fmt.Sscanf(cached[idx+1:], "%f", &cachedScore)
				}
				if m := MetricsFromContext(ctx); m != nil {
					m.AIClassification = classification
					if cachedScore > m.ThreatScore {
						m.ThreatScore = cachedScore
					}
				}
				if classification == "malicious" {
					writeBlockError(w, "AI_BLOCKED", "request classified as malicious (cached)")
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			// Determine if this path should use fail-closed mode
			failClosed := cfg.FailClosed
			if !failClosed {
				for _, p := range cfg.FailClosedPaths {
					if strings.HasPrefix(r.URL.Path, p) {
						failClosed = true
						break
					}
				}
			}

			// Call AI with timeout
			aiCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			classification, err := router.ClassifyRequest(aiCtx, features)
			if err != nil {
				if failClosed {
					// Fail-closed: block request if AI unavailable
					log.Printf("classify: AI error, blocking request (fail-closed): %v", err)
					writeBlockError(w, "AI_UNAVAILABLE", "AI classification unavailable, request blocked")
					return
				}
				// Fail-open: log error but allow request through (other middleware still applies)
				log.Printf("classify: AI error, allowing request (fail-open): %v", err)
				next.ServeHTTP(w, r)
				return
			}

			// Cache the result (60s TTL) — store classification:score
			rdb.Set(ctx, cacheKey, fmt.Sprintf("%s:%.4f", classification.Classification, classification.Score), 60*time.Second)

			// Store in metrics for logging middleware — only update score if higher (preserve rule scores)
			if m := MetricsFromContext(ctx); m != nil {
				m.AIClassification = classification.Classification
				if classification.Score > m.ThreatScore {
					m.ThreatScore = classification.Score
				}
			}

			// Update Redis stats
			rdb.Incr(ctx, "stats:requests:total")
			rdb.ZIncrBy(ctx, "stats:top_ips", 1, ipStr)
			rdb.ZIncrBy(ctx, "stats:top_endpoints", 1, r.URL.Path)

			switch classification.Classification {
			case "malicious":
				rdb.Incr(ctx, "stats:requests:blocked")
				log.Printf("classify: blocked %s %s (score: %.2f, reason: %s)",
					r.Method, sanitizeLog(r.URL.Path), classification.Score, sanitizeLog(classification.Reasoning))
				writeBlockError(w, "AI_BLOCKED",
					"request classified as malicious")
				return
			case "suspicious":
				log.Printf("classify: suspicious %s %s (score: %.2f, reason: %s)",
					r.Method, sanitizeLog(r.URL.Path), classification.Score, sanitizeLog(classification.Reasoning))
				// Allow but log
			default:
				// benign — continue
			}

			rdb.Incr(ctx, "stats:requests:allowed")
			next.ServeHTTP(w, r)
		})
	}
}

// sanitizeLog strips newlines, control chars, and ANSI escapes to prevent log injection.
func sanitizeLog(s string) string {
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\t", "\\t")
	// Strip ANSI escape sequences
	if strings.Contains(s, "\x1b") {
		var b strings.Builder
		for _, r := range s {
			if r < 0x20 && r != '\t' || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
				b.WriteString(fmt.Sprintf("\\x%02x", r))
			} else {
				b.WriteRune(r)
			}
		}
		return b.String()
	}
	return s
}

func hashString(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// requestHash builds the FULL hash including User-Agent and QueryParams.
// Kept for callers that want a key that distinguishes clients.
func requestHash(features ai.RequestFeatures) string {
	h := sha256.Sum256([]byte(features.Method + features.Path + features.QueryParams + features.UserAgent + features.BodyHash))
	return hex.EncodeToString(h[:])
}

// canonicalRequestHash builds the AI cache key.
//
// F48 + cache-key-consistency:
//   - Path is decoded so percent-encoding does not split cache rows.
//   - Query params are sorted by key (and value) so re-ordering
//     doesn't bypass a cached decision.
//   - Raw query strings are NOT used directly: an attacker can flood
//     unbounded unique cache entries by appending random query bytes.
//   - Consistent with r.URL.RequestURI() framing: same path+query
//     always hashes to the same value.
func canonicalRequestHash(features ai.RequestFeatures) string {
	decoded, err := url.QueryUnescape(features.Path)
	if err != nil {
		decoded = features.Path
	}
	q, err := url.ParseQuery(features.QueryParams)
	var stableQuery string
	if err == nil && len(q) > 0 {
		keys := make([]string, 0, len(q))
		for k := range q {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var parts []string
		for _, k := range keys {
			vs := append([]string(nil), q[k]...)
			sort.Strings(vs)
			for _, v := range vs {
				parts = append(parts, k+"="+v)
			}
		}
		stableQuery = strings.Join(parts, "&")
	}
	h := sha256.Sum256([]byte(features.Method + "\x00" + decoded + "\x00" + stableQuery + "\x00" + features.BodyHash))
	return hex.EncodeToString(h[:])
}
