package api

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/user/waf/internal/audit"
	"github.com/user/waf/internal/auth"
	wafmw "github.com/user/waf/internal/middleware"
)

// ExportHandler handles log export endpoints.
type ExportHandler struct {
	pool  *pgxpool.Pool
	audit *audit.Logger
	rdb   *redis.Client
}

// NewExportHandler creates a new export handler.
func NewExportHandler(pool *pgxpool.Pool, auditLog *audit.Logger, rdb *redis.Client) *ExportHandler {
	return &ExportHandler{pool: pool, audit: auditLog, rdb: rdb}
}

// ExportLogs handles GET /api/v1/logs/export
func (h *ExportHandler) ExportLogs(w http.ResponseWriter, r *http.Request) {
	if h.pool == nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", "database not available")
		return
	}

	// Rate limit: max 1 export per hour per user
	if h.rdb != nil {
		ctx := r.Context()
		claims := auth.ClaimsFromContext(ctx)
		if claims != nil {
			key := fmt.Sprintf("export:ratelimit:%d", claims.UserID)
			allowed, err := h.rdb.SetNX(ctx, key, "1", time.Hour).Result()
			if err != nil {
				log.Printf("export: rate limit check failed: %v", err)
			} else if !allowed {
				RespondError(w, http.StatusTooManyRequests, "RATE_LIMITED", "export rate limited: 1 per hour")
				return
			}
		}
	}

	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	// Build query with optional filters
	q := `SELECT id, timestamp::text, client_ip::text, method, host, path,
		COALESCE(query, ''), COALESCE(user_agent, ''), action,
		COALESCE(threat_score, 0), COALESCE(ai_classification, ''),
		COALESCE(response_code, 0), COALESCE(response_time_ms, 0),
		COALESCE(country, '')
		FROM request_logs WHERE 1=1`
	args := []interface{}{}
	argIdx := 1

	if ip := r.URL.Query().Get("ip"); ip != "" {
		q += " AND client_ip = $" + strconv.Itoa(argIdx)
		args = append(args, ip)
		argIdx++
	}
	if action := r.URL.Query().Get("action"); action != "" {
		q += " AND action = $" + strconv.Itoa(argIdx)
		args = append(args, action)
		argIdx++
	}

	q += " ORDER BY timestamp DESC LIMIT 10000"

	rows, err := h.pool.Query(ctx, q, args...)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "database"))
		return
	}
	defer rows.Close()

	type logRow struct {
		ID               int     `json:"id"`
		Timestamp        string  `json:"timestamp"`
		ClientIP         string  `json:"client_ip"`
		Method           string  `json:"method"`
		Host             string  `json:"host"`
		Path             string  `json:"path"`
		Query            string  `json:"query"`
		UserAgent        string  `json:"user_agent"`
		Action           string  `json:"action"`
		ThreatScore      float64 `json:"threat_score"`
		AIClassification string  `json:"ai_classification"`
		ResponseCode     int     `json:"response_code"`
		ResponseTimeMs   int     `json:"response_time_ms"`
		Country          string  `json:"country"`
	}

	var results []logRow
	for rows.Next() {
		var row logRow
		if err := rows.Scan(&row.ID, &row.Timestamp, &row.ClientIP, &row.Method,
			&row.Host, &row.Path, &row.Query, &row.UserAgent, &row.Action,
			&row.ThreatScore, &row.AIClassification, &row.ResponseCode,
			&row.ResponseTimeMs, &row.Country); err != nil {
			RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "database"))
			return
		}
		results = append(results, row)
	}

	// Audit log the export
	if h.audit != nil {
		var uid int
		var uname string
		if c := auth.ClaimsFromContext(r.Context()); c != nil {
			uid, uname = c.UserID, c.Username
		}
		ip := wafmw.ExtractClientIP(r)
		h.audit.Log(audit.Entry{
			UserID:       uid,
			Username:     uname,
			Action:       "export",
			ResourceType: "logs",
			ResourceID:   fmt.Sprintf("%d_rows", len(results)),
			Details:      map[string]string{"format": format, "filters": r.URL.RawQuery},
			IPAddress:    ip,
		})
	}

	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=aegis-logs-%s.csv", time.Now().Format("2006-01-02")))

		writer := csv.NewWriter(w)
		writer.Write([]string{"id", "timestamp", "client_ip", "method", "host", "path",
			"query", "user_agent", "action", "threat_score", "ai_classification",
			"response_code", "response_time_ms", "country"})
		for _, row := range results {
			writer.Write([]string{
				strconv.Itoa(row.ID), row.Timestamp, row.ClientIP, row.Method,
				row.Host, row.Path, row.Query, row.UserAgent, row.Action,
				fmt.Sprintf("%.2f", row.ThreatScore), row.AIClassification,
				strconv.Itoa(row.ResponseCode), strconv.Itoa(row.ResponseTimeMs),
				row.Country,
			})
		}
		writer.Flush()

	default: // json
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=aegis-logs-%s.json", time.Now().Format("2006-01-02")))
		json.NewEncoder(w).Encode(results)
	}
}
