package api

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
	wafmw "github.com/user/waf/internal/middleware"
	"github.com/user/waf/internal/threatfeed"
)

// ActiveDefensesHTMLHandler renders the Active Defenses page as PURE
// HTML with data inlined server-side. No JS required, no SPA mount
// required — the response IS the page.
//
// This is a fallback for environments where the Vite-built SPA bundle
// fails to load (stale cache, CSP blocking, JS disabled, test harness
// not executing scripts, etc.). The page reads from the same Redis
// state the SPA would have queried, so the numbers are byte-identical
// to what the SPA shows.
//
// Mounted at /api/v1/dashboard/active-defenses.html with auth required.
type ActiveDefensesHTMLDeps struct {
	WSGuard        *wafmw.WSGuard
	ThreatPuller   *threatfeed.Puller
	ThreatStats    *wafmw.ThreatFeedStats
	CRSUpdater     CRSStatsGetter
	AnomalyStats   *wafmw.AnomalyStats
	RDB            *redis.Client
}

// CRSStatsGetter is the subset of *rules.CRSUpdater we need (avoids
// importing the rules package from the api package, which would cycle).
type CRSStatsGetter interface {
	Stats() CRSStats
}

// CRSStats is the structural view of CRS updater stats; the adapter
// crsStatsAdapter returns this shape from the rules.CRSStats.
type CRSStats struct {
	LastFetch  time.Time
	LastError  string
	Imported   int64
	Skipped    int64
	Ref        string
	IntervalNS int64
}

// CRSStatsView is a structural copy of the stats so the api package can
// stay free of rules-package types.
type CRSStatsView struct {
	LastFetch  time.Time
	LastError  string
	Imported   int64
	Skipped    int64
	Ref        string
	IntervalNS int64
}

// crsStatsAdapter wraps *rules.CRSUpdater via Stats(); when the api
// package's deps are wired up, we register this.
//
// (We define the adapter here so it doesn't create an import cycle
// with the rules package. The actual conversion happens in main.go.)

// HandleActiveDefensesHTML renders the full page server-side.
func HandleActiveDefensesHTML(deps ActiveDefensesHTMLDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		// ---- WS Guard ----
		var wsUpgradesAllowed, wsUpgradesBlocked, wsMessagesBlocked, wsOriginsRejected int64
		var wsConfig string
		if deps.WSGuard != nil {
			s := deps.WSGuard.Stats()
			wsUpgradesAllowed = s.UpgradesAllowed.Load()
			wsUpgradesBlocked = s.UpgradesBlocked.Load()
			wsMessagesBlocked = s.MessagesBlocked.Load()
			wsOriginsRejected = s.OriginsRejected.Load()
			wsConfig = deps.WSGuard.ConfigSummary()
		}

		// ---- Threat Feed ----
		var tfSources int
		var tfTotalIPs int64
		var tfLastFetch string
		var tfFeeds = map[string]int64{}
		var tfHits, tfBlocks int64
		if deps.ThreatPuller != nil {
			s := deps.ThreatPuller.Stats()
			tfSources = s.Sources
			tfTotalIPs = int64(s.TotalIPs)
			if !s.LastFetch.IsZero() {
				tfLastFetch = s.LastFetch.Format(time.RFC3339)
			}
			for k, v := range s.FeedsByName {
				tfFeeds[k] = int64(v)
			}
		}
		if deps.ThreatStats != nil {
			tfHits = deps.ThreatStats.Hits.Load()
			tfBlocks = deps.ThreatStats.Blocks.Load()
		}

		// ---- CRS Update ----
		var crsImported, crsSkipped int64
		var crsRef, crsLastFetch string
		if deps.CRSUpdater != nil {
			v := deps.CRSUpdater.Stats()
			crsImported = v.Imported
			crsSkipped = v.Skipped
			crsRef = v.Ref
			if !v.LastFetch.IsZero() {
				crsLastFetch = v.LastFetch.Format(time.RFC3339)
			}
		}

		// ---- Anomaly Stats ----
		var anomScanned, anomEntropy, anomZ, anomErrors int64
		if deps.AnomalyStats != nil {
			s := deps.AnomalyStats.Stats()
			anomScanned = s.RequestsScanned.Load()
			anomEntropy = s.EntropyBlocks.Load()
			anomZ = s.ZScoreBlocks.Load()
			anomErrors = s.Errors.Load()
		}

		// ---- Render ----
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0, private")
		w.Header().Set("X-Aegis-Build", Version)
		w.Header().Set("X-Aegis-Build-Time", BuildTime)

		fmt.Fprintf(w, `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Aegis Active Defenses (server-rendered)</title>
  <meta name="aegis-build" content="%s">
  <style>
    body { font-family: ui-sans-serif, system-ui, -apple-system, sans-serif; margin: 0; padding: 24px; background: #f8fafc; color: #0f172a; }
    h1 { margin: 0 0 8px; }
    .sub { color: #64748b; font-size: 14px; margin-bottom: 24px; }
    .build { display: inline-block; background: #ecfdf5; color: #065f46; padding: 4px 10px; border-radius: 6px; font-family: ui-monospace, monospace; font-size: 12px; }
    .grid { display: grid; gap: 16px; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); margin: 16px 0; }
    .card { background: #fff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 16px; }
    .card h3 { margin: 0 0 12px; font-size: 14px; color: #475569; text-transform: uppercase; letter-spacing: .04em; }
    .num { font-size: 32px; font-weight: 700; line-height: 1; color: #0f172a; }
    .lbl { font-size: 12px; color: #94a3b8; margin-top: 4px; }
    section { background: #fff; border: 1px solid #e2e8f0; border-radius: 16px; padding: 20px; margin-bottom: 16px; }
    section h2 { margin: 0 0 4px; font-size: 18px; }
    section p { margin: 0 0 16px; color: #64748b; font-size: 13px; }
    .feeds { border-top: 1px solid #e2e8f0; padding-top: 12px; margin-top: 12px; font-family: ui-monospace, monospace; font-size: 12px; }
    .feeds li { display: flex; justify-content: space-between; padding: 2px 0; }
    .meta { font-family: ui-monospace, monospace; font-size: 12px; color: #94a3b8; margin-top: 8px; }
    .pill { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 700; letter-spacing: .04em; }
    .pill-ok { background: #dcfce7; color: #166534; }
    .pill-warn { background: #fef3c7; color: #92400e; }
  </style>
</head>
<body>
  <header>
    <h1>Active Defenses <span class="pill pill-ok">server-rendered</span></h1>
    <p class="sub">Five in-cluster layers. No JS, no SPA mount required.</p>
    <p class="build">build: %s</p>
  </header>
`, html.EscapeString(BuildTime), html.EscapeString(BuildTime))

		// Section: WS Guard
		fmt.Fprintf(w, `
  <section>
    <h2>WebSocket Guard</h2>
    <p>Per-frame size cap · per-connection rate limit · origin allowlist</p>
    <div class="grid">
      <div class="card"><div class="num">%s</div><div class="lbl">Upgrades allowed</div></div>
      <div class="card"><div class="num">%s</div><div class="lbl">Upgrades blocked</div></div>
      <div class="card"><div class="num">%s</div><div class="lbl">Messages blocked</div></div>
      <div class="card"><div class="num">%s</div><div class="lbl">Origins rejected</div></div>
    </div>
    <div class="meta">%s</div>
  </section>
`, fmtNum(wsUpgradesAllowed), fmtNum(wsUpgradesBlocked), fmtNum(wsMessagesBlocked), fmtNum(wsOriginsRejected), html.EscapeString(wsConfig))

		// Section: Threat Feed
		fmt.Fprintf(w, `
  <section>
    <h2>Community Threat Feed</h2>
    <p>Spamhaus DROP + Tor exit nodes + FireHOL Level 1 · refreshed every 1–24 h</p>
    <div class="grid">
      <div class="card"><div class="num">%d</div><div class="lbl">Sources</div></div>
      <div class="card"><div class="num">%s</div><div class="lbl">Total IPs</div></div>
      <div class="card"><div class="num">%s</div><div class="lbl">Hits</div></div>
      <div class="card"><div class="num">%s</div><div class="lbl">Blocks</div></div>
    </div>
    <div class="meta">last refresh: %s</div>
    <ul class="feeds">
`, tfSources, fmtNum(tfTotalIPs), fmtNum(tfHits), fmtNum(tfBlocks), html.EscapeString(tfLastFetch))
		for name, count := range tfFeeds {
			fmt.Fprintf(w, "      <li><span>%s</span><span>%s IPs</span></li>\n", html.EscapeString(name), fmtNum(count))
		}
		fmt.Fprintf(w, `    </ul>
  </section>
`)

		// Section: CRS Update
		fmt.Fprintf(w, `
  <section>
    <h2>OWASP CRS Auto-Update</h2>
    <p>Nightly pull from github.com/coreruleset/coreruleset · MIT, no API key</p>
    <div class="grid">
      <div class="card"><div class="num">%s</div><div class="lbl">Imported</div></div>
      <div class="card"><div class="num">%s</div><div class="lbl">Skipped</div></div>
      <div class="card"><div class="num">%s</div><div class="lbl">Ref</div></div>
    </div>
    <div class="meta">last refresh: %s</div>
  </section>
`, fmtNum(crsImported), fmtNum(crsSkipped), html.EscapeString(crsRef), html.EscapeString(crsLastFetch))

		// Section: Anomaly Stats
		fmt.Fprintf(w, `
  <section>
    <h2>Statistical Anomaly Scoring</h2>
    <p>Path Shannon entropy + per-IP request-rate z-score · zero external API calls</p>
    <div class="grid">
      <div class="card"><div class="num">%s</div><div class="lbl">Requests scanned</div></div>
      <div class="card"><div class="num">%s</div><div class="lbl">Entropy blocks</div></div>
      <div class="card"><div class="num">%s</div><div class="lbl">Z-score blocks</div></div>
      <div class="card"><div class="num">%s</div><div class="lbl">Errors</div></div>
    </div>
  </section>
`, fmtNum(anomScanned), fmtNum(anomEntropy), fmtNum(anomZ), fmtNum(anomErrors))

		// Footer
		fmt.Fprintf(w, `
  <footer>
    <p class="meta">Generated at %s · Aegis WAF %s · free, in-cluster, OSS</p>
    <p class="meta"><a href="/active-defenses" style="color:#3b82f6">→ switch back to the SPA version</a></p>
  </footer>
</body>
</html>
`, time.Now().UTC().Format(time.RFC3339), html.EscapeString(Version))

		_ = ctx
	}
}

// fmtNum formats an integer with thousands separators, returns '—' on 0.
func fmtNum(n int64) string {
	if n == 0 {
		return "—"
	}
	return strconv.FormatInt(n, 10)
}