package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DashboardHandler handles dashboard aggregation endpoints.
type DashboardHandler struct {
	pool *pgxpool.Pool
}

// NewDashboardHandler creates a new dashboard handler.
func NewDashboardHandler(pool *pgxpool.Pool) *DashboardHandler {
	return &DashboardHandler{pool: pool}
}

// Overview handles GET /api/v1/dashboard/overview
//
// Time window is the same as the Traffic page default — the last 24h
// rolling. That keeps the Total Requests KPI on /overview identical
// to the sum of the get+post+put+delete buckets on /traffic (when the
// 24h pill is selected).
func (h *DashboardHandler) Overview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Anchor = now; the "since" for both current 24h window and the
	// previous-24h comparator is anchored here so the trend % matches
	// the apples-to-apples comparison the Traffic page uses.
	now := time.Now().UTC()
	since := now.Add(-24 * time.Hour)
	sinceYesterday := now.Add(-48 * time.Hour)

	var totalRequests, blockedCount, uniqueIPs int64
	var topThreatType string
	var topThreatCount int64

	err := h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM request_logs WHERE timestamp >= $1`, since).Scan(&totalRequests)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "overview query"))
		return
	}

	_ = h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM request_logs WHERE timestamp >= $1 AND action = 'blocked'`, since).Scan(&blockedCount)

	_ = h.pool.QueryRow(ctx,
		`SELECT COUNT(DISTINCT client_ip) FROM request_logs WHERE timestamp >= $1`, since).Scan(&uniqueIPs)

	// F57: empty-string classification. We deliberately coalesce
	// ai_classification to '' (rather than filter on IS NULL) so that
	// downstream consumers can rely on the same convention across the
	// dashboard — an empty string means "no classification recorded".
	_ = h.pool.QueryRow(ctx,
		`SELECT COALESCE(ai_classification, ''), COUNT(*) as cnt
		 FROM request_logs
		 WHERE timestamp >= $1 AND ai_classification IS NOT NULL AND ai_classification != 'benign'
		 GROUP BY ai_classification ORDER BY cnt DESC LIMIT 1`, since).Scan(&topThreatType, &topThreatCount)

	// Trend comparator: previous 24h (the same shape, just shifted by
	// 24h) so the % is an honest same-shape-vs-same-shape diff.
	var prevRequests, prevBlocked int64
	_ = h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM request_logs WHERE timestamp >= $1 AND timestamp < $2`, sinceYesterday, since).Scan(&prevRequests)
	_ = h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM request_logs WHERE timestamp >= $1 AND timestamp < $2 AND action = 'blocked'`, sinceYesterday, since).Scan(&prevBlocked)

	var requestsTrend, blockedTrend float64
	if prevRequests > 0 {
		requestsTrend = float64(totalRequests-prevRequests) / float64(prevRequests) * 100
	}
	if prevBlocked > 0 {
		blockedTrend = float64(blockedCount-prevBlocked) / float64(prevBlocked) * 100
	}

	topThreat := map[string]interface{}{}
	if topThreatType != "" {
		topThreat["type"] = topThreatType
		topThreat["count"] = topThreatCount
	}

	RespondJSON(w, http.StatusOK, map[string]interface{}{
		"total_requests":  totalRequests,
		"blocked_count":   blockedCount,
		"unique_ips":      uniqueIPs,
		"top_threat":      topThreat,
		"requests_trend":  requestsTrend,
		"blocked_trend":   blockedTrend,
	})
}

// Traffic handles GET /api/v1/dashboard/traffic
func (h *DashboardHandler) Traffic(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Use parameterized query to prevent SQL injection
	var since time.Time
	switch r.URL.Query().Get("range") {
	case "6h":
		since = time.Now().UTC().Add(-6 * time.Hour)
	case "24h":
		since = time.Now().UTC().Add(-24 * time.Hour)
	default:
		since = time.Now().UTC().Add(-1 * time.Hour)
	}

	rows, err := h.pool.Query(ctx,
		`SELECT date_trunc('minute', timestamp) as bucket,
			COUNT(*) AS total,
			COUNT(*) FILTER (WHERE method = 'GET') as get_count,
			COUNT(*) FILTER (WHERE method = 'POST') as post_count,
			COUNT(*) FILTER (WHERE method = 'PUT') as put_count,
			COUNT(*) FILTER (WHERE method = 'DELETE') as delete_count
		 FROM request_logs
		 WHERE timestamp >= $1
		 GROUP BY bucket ORDER BY bucket`, since)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "traffic query"))
		return
	}
	defer rows.Close()

	var result []map[string]interface{}
	for rows.Next() {
		var bucket interface{}
		var total, get, post, put, del int64
		if err := rows.Scan(&bucket, &total, &get, &post, &put, &del); err != nil {
			continue
		}
		result = append(result, map[string]interface{}{
			"timestamp": bucket,
			"total":     total,
			"get":       get,
			"post":      post,
			"put":       put,
			"delete":    del,
		})
	}
	if result == nil {
		result = []map[string]interface{}{}
	}
	RespondJSON(w, http.StatusOK, result)
}

// Threats handles GET /api/v1/dashboard/threats — aggregated classification counts for Overview
func (h *DashboardHandler) Threats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	rows, err := h.pool.Query(ctx,
		`SELECT COALESCE(NULLIF(ai_classification, ''), 'benign') as classification, COUNT(*) as count
		 FROM request_logs
		 WHERE timestamp >= CURRENT_DATE
		 GROUP BY classification`)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "threats query"))
		return
	}
	defer rows.Close()

	result := map[string]int64{"benign": 0, "suspicious": 0, "malicious": 0}
	for rows.Next() {
		var classification string
		var count int64
		if err := rows.Scan(&classification, &count); err != nil {
			continue
		}
		result[classification] = count
	}
	RespondJSON(w, http.StatusOK, result)
}

// ThreatEvents handles GET /api/v1/dashboard/threat-events — individual threat entries for ThreatCenter.
// Optional ?minutes=N window (default 60). The response only includes events
// that the WAF classified as a threat (high threat_score OR non-benign AI tag).
func (h *DashboardHandler) ThreatEvents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Default 60-minute window. Capped at 24h to avoid pulling the entire DB.
	minutes := 60
	if s := r.URL.Query().Get("minutes"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			if n > 24*60 {
				n = 24 * 60
			}
			minutes = n
		}
	}

	rows, err := h.pool.Query(ctx,
		`SELECT id, timestamp, client_ip::text, method, path, action,
			COALESCE(threat_score, 0), COALESCE(ai_classification, '')
		 FROM request_logs
		 WHERE timestamp >= NOW() - ($1 || ' minutes')::interval
		   AND (COALESCE(threat_score, 0) > 0.3 OR ai_classification NOT IN ('', 'benign'))
		 ORDER BY timestamp DESC LIMIT 100`,
		strconv.Itoa(minutes))
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "threat events query"))
		return
	}
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "threat events query"))
		return
	}
	defer rows.Close()

	type threatEvent struct {
		ID               int64     `json:"id"`
		Timestamp        time.Time `json:"timestamp"`
		ClientIP         string    `json:"client_ip"`
		Method           string    `json:"method"`
		Path             string    `json:"path"`
		Action           string    `json:"action"`
		ThreatScore      float64   `json:"threat_score"`
		AIClassification string    `json:"ai_classification"`
	}

	var result []threatEvent
	for rows.Next() {
		var t threatEvent
		if err := rows.Scan(&t.ID, &t.Timestamp, &t.ClientIP, &t.Method, &t.Path,
			&t.Action, &t.ThreatScore, &t.AIClassification); err != nil {
			continue
		}
		result = append(result, t)
	}
	if result == nil {
		result = []threatEvent{}
	}
	RespondJSON(w, http.StatusOK, result)
}

// TopEndpoints handles GET /api/v1/dashboard/top-endpoints
func (h *DashboardHandler) TopEndpoints(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	rows, err := h.pool.Query(ctx,
		`SELECT path,
				COUNT(*) AS count,
				COUNT(*) FILTER (WHERE action = 'blocked') AS blocked,
				COALESCE(AVG(response_time_ms)::int, 0) AS avg_response_ms,
				COALESCE(AVG(threat_score)::float, 0) AS avg_threat_score
		 FROM request_logs
		 WHERE timestamp >= CURRENT_DATE
		 GROUP BY path ORDER BY count DESC LIMIT 10`)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "top endpoints query"))
		return
	}
	defer rows.Close()

	var result []map[string]interface{}
	for rows.Next() {
		var path string
		var count, blocked, avgMs int64
		var avgThreat float64
		if err := rows.Scan(&path, &count, &blocked, &avgMs, &avgThreat); err != nil {
			continue
		}
		result = append(result, map[string]interface{}{
			"path":             path,
			"count":            count,
			"blocked":          blocked,
			"avg_response_ms":  avgMs,
			"avg_threat_score": avgThreat,
		})
	}
	if result == nil {
		result = []map[string]interface{}{}
	}
	RespondJSON(w, http.StatusOK, result)
}

// GeoAttacks handles GET /api/v1/dashboard/geo-attacks
// Returns top attacking IPs grouped by country for globe visualization.
func (h *DashboardHandler) GeoAttacks(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	rows, err := h.pool.Query(ctx,
		`SELECT client_ip::text, COALESCE(country, 'unknown') as country, COUNT(*) as count
		 FROM request_logs
		 WHERE timestamp >= CURRENT_DATE
		   AND action ILIKE 'block%'
		 GROUP BY client_ip, country
		 ORDER BY count DESC LIMIT 50`)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "geo attacks query"))
		return
	}
	defer rows.Close()

	var result []map[string]interface{}
	for rows.Next() {
		var ip, country string
		var count int64
		if err := rows.Scan(&ip, &country, &count); err != nil {
			continue
		}
		result = append(result, map[string]interface{}{
			"ip":      ip,
			"country": country,
			"count":   count,
		})
	}
	if result == nil {
		result = []map[string]interface{}{}
	}
	RespondJSON(w, http.StatusOK, result)
}

// StatusCodes handles GET /api/v1/dashboard/status-codes
func (h *DashboardHandler) StatusCodes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rows, err := h.pool.Query(ctx,
		`SELECT COALESCE(response_code, 0) as code, COUNT(*) as count
		 FROM request_logs WHERE timestamp >= CURRENT_DATE
		 GROUP BY code ORDER BY count DESC LIMIT 10`)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "status codes query"))
		return
	}
	defer rows.Close()
	var result []map[string]interface{}
	for rows.Next() {
		var code int
		var count int64
		if err := rows.Scan(&code, &count); err != nil {
			continue
		}
		result = append(result, map[string]interface{}{"code": code, "count": count})
	}
	if result == nil {
		result = []map[string]interface{}{}
	}
	RespondJSON(w, http.StatusOK, result)
}

// TopAttackedURLs handles GET /api/v1/dashboard/top-attacked-urls
func (h *DashboardHandler) TopAttackedURLs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rows, err := h.pool.Query(ctx,
		`SELECT path, COUNT(*) as count,
			COUNT(*) FILTER (WHERE action = 'blocked') as blocked
		 FROM request_logs WHERE timestamp >= CURRENT_DATE
		 GROUP BY path ORDER BY count DESC LIMIT 10`)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "top attacked urls query"))
		return
	}
	defer rows.Close()
	var result []map[string]interface{}
	for rows.Next() {
		var path string
		var count, blocked int64
		if err := rows.Scan(&path, &count, &blocked); err != nil {
			continue
		}
		result = append(result, map[string]interface{}{"path": path, "count": count, "blocked": blocked})
	}
	if result == nil {
		result = []map[string]interface{}{}
	}
	RespondJSON(w, http.StatusOK, result)
}

// AttackTypes handles GET /api/v1/dashboard/attack-types
func (h *DashboardHandler) AttackTypes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rows, err := h.pool.Query(ctx,
		`SELECT COALESCE(NULLIF(rl.ai_classification, ''), 'unknown') as type, COUNT(*) as count
		 FROM request_logs rl
		 WHERE rl.timestamp >= CURRENT_DATE AND rl.action = 'blocked'
		 GROUP BY type ORDER BY count DESC LIMIT 10`)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "attack types query"))
		return
	}
	defer rows.Close()
	var result []map[string]interface{}
	for rows.Next() {
		var typ string
		var count int64
		if err := rows.Scan(&typ, &count); err != nil {
			continue
		}
		result = append(result, map[string]interface{}{"type": typ, "count": count})
	}
	if result == nil {
		result = []map[string]interface{}{}
	}
	RespondJSON(w, http.StatusOK, result)
}

// Bandwidth handles GET /api/v1/dashboard/bandwidth
func (h *DashboardHandler) Bandwidth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var since time.Time
	switch r.URL.Query().Get("range") {
	case "6h":
		since = time.Now().UTC().Add(-6 * time.Hour)
	case "24h":
		since = time.Now().UTC().Add(-24 * time.Hour)
	default:
		since = time.Now().UTC().Add(-1 * time.Hour)
	}
	rows, err := h.pool.Query(ctx,
		`SELECT date_trunc('minute', timestamp) as bucket,
			SUM(COALESCE(bytes_sent, 0)) as bytes_out,
			SUM(COALESCE(bytes_received, 0)) as bytes_in
		 FROM request_logs WHERE timestamp >= $1
		 GROUP BY bucket ORDER BY bucket`, since)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "bandwidth query"))
		return
	}
	defer rows.Close()
	var result []map[string]interface{}
	for rows.Next() {
		var bucket interface{}
		var bytesOut, bytesIn int64
		if err := rows.Scan(&bucket, &bytesOut, &bytesIn); err != nil {
			continue
		}
		result = append(result, map[string]interface{}{"time": bucket, "bytes_out": bytesOut, "bytes_in": bytesIn})
	}
	if result == nil {
		result = []map[string]interface{}{}
	}
	RespondJSON(w, http.StatusOK, result)
}

// TopIPs handles GET /api/v1/dashboard/top-ips
func (h *DashboardHandler) TopIPs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	rows, err := h.pool.Query(ctx,
		`SELECT client_ip::text, COUNT(*) as count,
			COUNT(*) FILTER (WHERE action = 'blocked') as blocked,
			COALESCE(MAX(country), '') as country,
			COALESCE(AVG(threat_score), 0) as avg_threat_score,
			MAX(timestamp) as last_seen
		 FROM request_logs
		 WHERE timestamp >= CURRENT_DATE
		 GROUP BY client_ip ORDER BY count DESC LIMIT 10`)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "top IPs query"))
		return
	}
	defer rows.Close()

	var result []map[string]interface{}
	for rows.Next() {
		var ip, country string
		var count, blocked int64
		var avgThreat float64
		var lastSeen interface{}
		if err := rows.Scan(&ip, &count, &blocked, &country, &avgThreat, &lastSeen); err != nil {
			continue
		}
		result = append(result, map[string]interface{}{
			"ip":              ip,
			"count":           count,
			"blocked":         blocked,
			"country":         country,
			"avg_threat_score": avgThreat,
			"last_seen":       lastSeen,
		})
	}
	if result == nil {
		result = []map[string]interface{}{}
	}
	RespondJSON(w, http.StatusOK, result)
}
