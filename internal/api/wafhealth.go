package api

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// WAFHealthHandler serves the "WAF Rules Health" widget data:
// top fired rules, false-positive rates, 24h trend.
type WAFHealthHandler struct {
	pool *pgxpool.Pool
}

// NewWAFHealthHandler creates a WAF health handler.
func NewWAFHealthHandler(pool *pgxpool.Pool) *WAFHealthHandler {
	return &WAFHealthHandler{pool: pool}
}

// TopFiredRule describes one WAF rule and its recent activity.
type TopFiredRule struct {
	RuleID         int     `json:"rule_id"`
	RuleName       string  `json:"rule_name"`
	Hits1h         int     `json:"hits_1h"`
	Hits24h        int     `json:"hits_24h"`
	FalsePos1h     int     `json:"false_pos_1h"`
	FalsePos24h    int     `json:"false_pos_24h"`
	FPRate         float64 `json:"fp_rate"` // false positive rate (0..1) over 24h
	Trend          []int   `json:"trend"`    // last 24 hourly bucket counts
	TopAction      string  `json:"top_action"`
}

// WAFHealthResponse is the full payload for the dashboard widget.
type WAFHealthResponse struct {
	TotalEvents24h     int            `json:"total_events_24h"`
	TotalBlocked24h    int            `json:"total_blocked_24h"`
	TotalAllowed24h    int            `json:"total_allowed_24h"`
	TopRules           []TopFiredRule `json:"top_rules"`
	TopAttackedURLs    []URLHit       `json:"top_attacked_urls"`
	TopAttackerIPs     []IPHit        `json:"top_attacker_ips"`
	UniqueSources24h   int            `json:"unique_sources_24h"`
	GeneratedAt        time.Time      `json:"generated_at"`
	IntervalHours      int            `json:"interval_hours"`
}

type URLHit struct {
	Path   string `json:"path"`
	Hits   int    `json:"hits"`
	Action string `json:"top_action"`
}

type IPHit struct {
	IP     string `json:"ip"`
	Hits   int    `json:"hits"`
	Action string `json:"top_action"`
}

// WAFHealth handles GET /api/v1/dashboard/waf-health
func (h *WAFHealthHandler) WAFHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	intervalHours := 24
	if s := r.URL.Query().Get("hours"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 && n <= 168 {
			intervalHours = n
		}
	}

	resp := WAFHealthResponse{
		IntervalHours: intervalHours,
		GeneratedAt:   time.Now().UTC(),
	}

	// Totals over the window.
	row := h.pool.QueryRow(ctx,
		`SELECT
		   COUNT(*),
		   COUNT(*) FILTER (WHERE action ILIKE 'block%'),
		   COUNT(*) FILTER (WHERE action ILIKE 'allow%'),
		   COUNT(DISTINCT client_ip)
		 FROM request_logs
		 WHERE timestamp >= NOW() - ($1 || ' hours')::interval`,
		strconv.Itoa(intervalHours))
	if err := row.Scan(&resp.TotalEvents24h, &resp.TotalBlocked24h, &resp.TotalAllowed24h, &resp.UniqueSources24h); err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "totals query"))
		return
	}

	// Top fired rules (1h vs 24h).
	ruleRows, err := h.pool.Query(ctx,
		`SELECT
		   rule_id,
		   COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '1 hour') AS h1,
		   COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '24 hours') AS h24,
		   COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '1 hour' AND action ILIKE 'allow%') AS fp1,
		   COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '24 hours' AND action ILIKE 'allow%') AS fp24,
		   (SELECT name FROM rules WHERE id = request_logs.rule_id) AS name,
		   MODE() WITHIN GROUP (ORDER BY action) AS top_action
		 FROM request_logs
		 WHERE rule_id IS NOT NULL AND timestamp >= NOW() - INTERVAL '24 hours'
		 GROUP BY rule_id
		 ORDER BY h24 DESC
		 LIMIT 8`, 0, 0)
	if err == nil {
		defer ruleRows.Close()
		// Build 24h hourly trend per rule in a second pass.
		for ruleRows.Next() {
			var r TopFiredRule
			var name *string
			var topAction *string
			if err := ruleRows.Scan(&r.RuleID, &r.Hits1h, &r.Hits24h, &r.FalsePos1h, &r.FalsePos24h, &name, &topAction); err != nil {
				continue
			}
			if r.Hits24h > 0 {
				r.FPRate = float64(r.FalsePos24h) / float64(r.Hits24h)
			}
			if name != nil {
				r.RuleName = *name
			} else {
				r.RuleName = "(unmatched)"
			}
			if topAction != nil {
				r.TopAction = *topAction
			}
			// Hourly trend.
			trendRows, terr := h.pool.Query(ctx,
				`SELECT
				   EXTRACT(HOUR FROM NOW() - ts)::int / 1 AS bucket,
				   COUNT(*)
				 FROM request_logs
				 WHERE rule_id = $1 AND ts := NOW() - ($2 || ' hours')::interval
				 GROUP BY bucket
				 ORDER BY bucket`,
				r.RuleID, strconv.Itoa(intervalHours))
			if terr == nil {
				buckets := make(map[int]int, 24)
				for trendRows.Next() {
					var b, c int
					if err := trendRows.Scan(&b, &c); err == nil {
						buckets[b] = c
					}
				}
				trendRows.Close()
				// Fill missing buckets with 0.
				for i := 0; i < 24 && i < intervalHours; i++ {
					r.Trend = append(r.Trend, buckets[i])
				}
			}
			resp.TopRules = append(resp.TopRules, r)
		}
	}

	// Top attacked URLs.
	urlRows, err := h.pool.Query(ctx,
		`SELECT path, COUNT(*) AS hits, MODE() WITHIN GROUP (ORDER BY action) AS top_action
		 FROM request_logs
		 WHERE action ILIKE 'block%' AND timestamp >= NOW() - INTERVAL '24 hours'
		 GROUP BY path
		 ORDER BY hits DESC
		 LIMIT 8`)
	if err == nil {
		defer urlRows.Close()
		for urlRows.Next() {
			var u URLHit
			var topAction *string
			if err := urlRows.Scan(&u.Path, &u.Hits, &topAction); err != nil {
				continue
			}
			if topAction != nil {
				u.Action = *topAction
			}
			resp.TopAttackedURLs = append(resp.TopAttackedURLs, u)
		}
	}

	// Top attacker IPs.
	ipRows, err := h.pool.Query(ctx,
		`SELECT client_ip::text, COUNT(*) AS hits, MODE() WITHIN GROUP (ORDER BY action) AS top_action
		 FROM request_logs
		 WHERE action ILIKE 'block%' AND timestamp >= NOW() - INTERVAL '24 hours'
		 GROUP BY client_ip
		 ORDER BY hits DESC
		 LIMIT 8`)
	if err == nil {
		defer ipRows.Close()
		for ipRows.Next() {
			var i IPHit
			var topAction *string
			if err := ipRows.Scan(&i.IP, &i.Hits, &topAction); err != nil {
				continue
			}
			if topAction != nil {
				i.Action = *topAction
			}
			resp.TopAttackerIPs = append(resp.TopAttackerIPs, i)
		}
	}

	if resp.TopRules == nil {
		resp.TopRules = []TopFiredRule{}
	}
	if resp.TopAttackedURLs == nil {
		resp.TopAttackedURLs = []URLHit{}
	}
	if resp.TopAttackerIPs == nil {
		resp.TopAttackerIPs = []IPHit{}
	}

	RespondJSON(w, http.StatusOK, resp)
}
