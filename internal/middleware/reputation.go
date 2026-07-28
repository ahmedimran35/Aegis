package middleware

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/user/waf/internal/reputation"
)

// ReputationMiddleware checks client IP reputation via the reputation client.
// If abuse confidence > threshold, the request is blocked.
// If confidence > 50, it's flagged as suspicious (added to threat score).
func ReputationMiddleware(repClient *reputation.Client, threshold int) Middleware {
	if threshold <= 0 {
		threshold = 80
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !repClient.IsEnabled() {
				next.ServeHTTP(w, r)
				return
			}

			ip := extractIP(r)
			if ip == nil {
				next.ServeHTTP(w, r)
				return
			}

			ipStr := ip.String()

			// Skip private IPs
			if isPrivateIPRep(ip) {
				next.ServeHTTP(w, r)
				return
			}

			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			defer cancel()

			result, err := repClient.CheckIP(ctx, ipStr)
			if err != nil {
				// Fail-open: log error but allow request. M-5: track
				// fail-open events so the operator can alert when the
				// reputation provider goes down instead of silently
				// weakening enforcement.
				log.Printf("reputation: check failed for %s: %v", ipStr, err)
				repClient.IncrFailOpen()
				next.ServeHTTP(w, r)
				return
			}

			// Store in metrics for logging
			if m := MetricsFromContext(r.Context()); m != nil {
				if result.AbuseConfidenceScore > 50 {
					// Add to threat score proportionally
					repScore := float64(result.AbuseConfidenceScore) / 100.0
					if repScore > m.ThreatScore {
						m.ThreatScore = repScore
					}
				}
			}

			// Block if above threshold
			if result.AbuseConfidenceScore >= threshold {
				repClient.IncrBlocked()
				log.Printf("reputation: blocked %s (score=%d, country=%s, reports=%d)",
					sanitizeLog(ipStr), result.AbuseConfidenceScore, result.CountryCode, result.TotalReports)
				writeBlockError(w, "IP_REPUTATION_BLOCKED",
					fmt.Sprintf("blocked by IP reputation (abuse score: %d%%)", result.AbuseConfidenceScore))
				return
			}

			// Flag suspicious but allow
			if result.AbuseConfidenceScore > 50 {
				log.Printf("reputation: suspicious %s (score=%d, country=%s)",
					sanitizeLog(ipStr), result.AbuseConfidenceScore, result.CountryCode)
			}

			next.ServeHTTP(w, r)
		})
	}
}

// isPrivateIPRep checks if an IP is private/loopback for the reputation middleware.
func isPrivateIPRep(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}
