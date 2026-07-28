package api

import (
	"net/http"
	"runtime"
	"time"

	"github.com/user/waf/internal/auth"
)

var systemStartTime = time.Now()

// Version returns the server-side build identifier. Set at process start
// via -ldflags "-X main.version=... -X main.buildTimeStr=...". Exposed via
// /api/v1/system/build (no auth) so the dashboard can compare it against
// its embedded VITE_BUILD_HASH and force a reload on mismatch.
var Version = "dev"

// BuildTime returns the server-side build timestamp. Same provenance as
// Version; surfaces in /api/v1/system/build.
var BuildTime = "unknown"

// SystemInfo holds system information (limited to avoid recon data leakage).
type SystemInfo struct {
	NumGoroutine int    `json:"num_goroutine"`
	Uptime       string `json:"uptime"`
}

// HandleSystemInfo handles GET /api/v1/system/info (admin-only)
func HandleSystemInfo(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil || claims.Role != "admin" {
		RespondError(w, http.StatusForbidden, "FORBIDDEN", "admin access required")
		return
	}

	RespondJSON(w, http.StatusOK, SystemInfo{
		NumGoroutine: runtime.NumGoroutine(),
		Uptime:       time.Since(systemStartTime).Round(time.Second).String(),
	})
}

// HandleSystemBuild handles GET /api/v1/system/build (public, no auth).
//
// Returns the server-side build identifier so the dashboard can detect
// when its embedded VITE_BUILD_HASH is out of date and reload. Designed
// to be the cheapest possible endpoint — no DB query, no JSON parsing
// on the client side (just a plain string).
func HandleSystemBuild(w http.ResponseWriter, r *http.Request) {
	// Cache-Control is deliberately omitted: the endpoint is intended
	// to be fetched fresh on every page load.
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Aegis-Build", Version)
	w.Header().Set("X-Aegis-Build-Time", BuildTime)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(Version))
}

// StatusProvider exposes the live counters used by HandleSystemStatus.
// Implemented by main.go via the same dependency struct as the HTML
// endpoint. Kept here as an interface so the api package stays free of
// imports on the middleware / threatfeed / rules packages.
type StatusProvider interface {
	WSGuardUpgradesAllowed() int64
	WSGuardUpgradesBlocked() int64
	WSGuardMessagesBlocked() int64
	WSGuardOriginsRejected() int64
	WSGuardFrameLimit() int64
	WSGuardConfigSummary() string

	ThreatFeedSources() int
	ThreatFeedTotalIPs() int64
	ThreatFeedLastFetch() string
	ThreatFeedFeeds() map[string]int64
	ThreatFeedHits() int64
	ThreatFeedBlocks() int64

	CRSImported() int64
	CRSSkipped() int64
	CRSRef() string
	CRSLastFetch() string

	AnomalyScanned() int64
	AnomalyEntropy() int64
	AnomalyZScore() int64
	AnomalyErrors() int64
}

// HandleSystemStatus handles GET /api/v1/system/status (public, no auth).
//
// Returns a plain-text, human-readable status report covering every
// counter the Active Defenses page exposes. Designed to be a fallback
// channel for any client (test harness, monitoring system, curl, AI
// agent) that cannot or will not render HTML/JS — they can paste the
// response verbatim and see exactly what the WAF is reporting right now.
//
// Output format is fixed-width so columns line up in monospace displays.
func HandleSystemStatus(sp StatusProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store, must-revalidate")
		w.Header().Set("X-Aegis-Build", Version)
		w.Header().Set("X-Aegis-Build-Time", BuildTime)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(renderStatusReport(sp)))
	}
}

func renderStatusReport(sp StatusProvider) string {
	if sp == nil {
		return "no status provider configured\n"
	}
	var b []byte
	w := func(s string) { b = append(b, s...) }
	line := func(left, right string) {
		w(left)
		w(": ")
		w(right)
		w("\n")
	}
	w("=== Aegis Active Defenses status ===\n")
	w("build:    " + Version + "\n")
	w("time:     " + BuildTime + "\n")
	w("now:      " + time.Now().UTC().Format(time.RFC3339) + "\n\n")

	w("Layer 1 — WebSocket Guard\n")
	line("  upgrades_allowed", itoa(sp.WSGuardUpgradesAllowed()))
	line("  upgrades_blocked", itoa(sp.WSGuardUpgradesBlocked()))
	line("  messages_blocked", itoa(sp.WSGuardMessagesBlocked()))
	line("  origins_rejected", itoa(sp.WSGuardOriginsRejected()))
	line("  frame_limit", itoa(sp.WSGuardFrameLimit()))
	line("  config", sp.WSGuardConfigSummary())
	w("\n")

	w("Layer 2 — Community Threat Feed\n")
	line("  sources", itoa(int64(sp.ThreatFeedSources())))
	line("  total_ips", itoa(sp.ThreatFeedTotalIPs()))
	line("  hits", itoa(sp.ThreatFeedHits()))
	line("  blocks", itoa(sp.ThreatFeedBlocks()))
	line("  last_fetch", sp.ThreatFeedLastFetch())
	w("  feeds:\n")
	for name, count := range sp.ThreatFeedFeeds() {
		w("    " + name + ": " + itoa(count) + " IPs\n")
	}
	w("\n")

	w("Layer 3 — OWASP CRS Auto-Update\n")
	line("  imported", itoa(sp.CRSImported()))
	line("  skipped", itoa(sp.CRSSkipped()))
	line("  ref", sp.CRSRef())
	line("  last_fetch", sp.CRSLastFetch())
	w("\n")

	w("Layer 4 — Statistical Anomaly Scoring\n")
	line("  requests_scanned", itoa(sp.AnomalyScanned()))
	line("  entropy_blocks", itoa(sp.AnomalyEntropy()))
	line("  zscore_blocks", itoa(sp.AnomalyZScore()))
	line("  errors", itoa(sp.AnomalyErrors()))
	w("\n")

	return string(b)
}

// itoa is a tiny helper to avoid strconv import noise in this file.
func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
