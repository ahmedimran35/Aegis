package middleware

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/user/waf/internal/rules"
)

const maxBodyRead int64 = 1 << 20 // 1MB

// RuleMiddleware wraps the rule engine as HTTP middleware with anomaly scoring.
func RuleMiddleware(engine *rules.Engine, paranoiaLevel, anomalyThreshold int) Middleware {
	return RuleMiddlewareWithPolicyTuner(engine, paranoiaLevel, anomalyThreshold, nil)
}

// RuleMiddlewareWithPolicyTuner wraps the rule engine with optional endpoint policy tuning.
func RuleMiddlewareWithPolicyTuner(engine *rules.Engine, paranoiaLevel, anomalyThreshold int, policyTuner *PolicyTuner) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := extractIP(r)

			// Read body for inspection (limit 1MB)
			body := readBody(r)

			// Get decoded query for rule matching
			decodedQuery, _ := url.QueryUnescape(r.URL.RawQuery)

			threshold := anomalyThreshold
			if policyTuner != nil {
				if tuned := policyTuner.GetThreshold(r.URL.Path); tuned > 0 {
					threshold = tuned
				}
			}

			// Use anomaly scoring — evaluate ALL rules
			result := engine.EvaluateAll(ip, r.Method, r.URL.Path, r.URL.RawQuery, r.UserAgent(), body, decodedQuery, paranoiaLevel)

			if result.Matched {
				// Check for explicit allow — skip further processing
				for _, mr := range result.MatchedRules {
					if mr.Action == rules.ActionAllow {
						next.ServeHTTP(w, r)
						return
					}
				}

				// Log all matched rules
				ruleNames := make([]string, len(result.MatchedRules))
				for i, mr := range result.MatchedRules {
					ruleNames[i] = fmt.Sprintf("%s(%s:%d)", mr.Name, mr.Severity, mr.SeverityScore())
				}

				// Store rule score in metrics for logging
				if m := MetricsFromContext(r.Context()); m != nil {
					m.RuleScore = result.Score
					m.MatchedRules = ruleNames
					// Normalize rule score to 0.0-1.0 for threat_score
					normalizedScore := float64(result.Score) / float64(threshold)
					if normalizedScore > 1.0 {
						normalizedScore = 1.0
					}
					if normalizedScore > m.ThreatScore {
						m.ThreatScore = normalizedScore
					}
					// Set classification based on rule action (AI can override later)
					if result.Score >= threshold && m.AIClassification == "" {
						m.AIClassification = "malicious"
					} else if m.AIClassification == "" {
						m.AIClassification = "suspicious"
					}
				}

				if result.Score >= threshold {
					// Block — anomaly score exceeds threshold
					log.Printf("rules: BLOCKED %s %s — score %d/%d, rules: [%s]",
						r.Method, sanitizeLog(r.URL.Path), result.Score, threshold,
						strings.Join(ruleNames, ", "))
					writeBlockError(w, "BLOCKED_BY_RULE",
						fmt.Sprintf("request blocked by Aegis (score: %d/%d)", result.Score, threshold))
					return
				}

				// Score below threshold — log as suspicious but allow
				log.Printf("rules: suspicious %s %s — score %d/%d, rules: [%s]",
					r.Method, sanitizeLog(r.URL.Path), result.Score, threshold,
					strings.Join(ruleNames, ", "))
			}

			next.ServeHTTP(w, r)
		})
	}
}

// readBody reads up to 1MB of the request body and restores it for downstream handlers.
func readBody(r *http.Request) string {
	if r.Body == nil || r.Body == http.NoBody {
		return ""
	}
	// Only read text-like content types
	ct := r.Header.Get("Content-Type")
	if ct != "" && !strings.HasPrefix(ct, "application/json") &&
		!strings.HasPrefix(ct, "application/x-www-form-urlencoded") &&
		!strings.HasPrefix(ct, "multipart/") &&
		!strings.HasPrefix(ct, "text/") {
		return ""
	}

	limited := io.LimitReader(r.Body, maxBodyRead)
	data, err := io.ReadAll(limited)
	if err != nil {
		return ""
	}
	// Restore body for downstream handlers
	r.Body = io.NopCloser(strings.NewReader(string(data)))
	return string(data)
}
