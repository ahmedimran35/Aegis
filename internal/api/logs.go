package api

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// LogHandler handles request log queries.
type LogHandler struct {
	pool *pgxpool.Pool
}

// NewLogHandler creates a new log handler.
func NewLogHandler(pool *pgxpool.Pool) *LogHandler {
	return &LogHandler{pool: pool}
}

type logEntry struct {
	ID               int     `json:"id"`
	Timestamp        string  `json:"timestamp"`
	ClientIP         string  `json:"client_ip"`
	Method           string  `json:"method"`
	Host             string  `json:"host"`
	Path             string  `json:"path"`
	Query            string  `json:"query"`
	Headers          []byte  `json:"headers"`
	UserAgent        string  `json:"user_agent"`
	Action           string  `json:"action"`
	ThreatScore      float64 `json:"threat_score"`
	AIClassification string  `json:"ai_classification"`
	ResponseCode     int     `json:"response_code"`
	ResponseTimeMs   int     `json:"response_time_ms"`
	Country          string  `json:"country"`
}

// List handles GET /api/v1/logs
func (h *LogHandler) List(w http.ResponseWriter, r *http.Request) {
	if h.pool == nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", "database not available")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	q := `SELECT id, timestamp::text, client_ip::text, method, host, path,
		COALESCE(query, ''), headers, COALESCE(user_agent, ''), action,
		COALESCE(threat_score, 0), COALESCE(ai_classification, ''),
		COALESCE(response_code, 0), COALESCE(response_time_ms, 0),
		COALESCE(country, '')
		FROM request_logs WHERE 1=1`
	args := []interface{}{}
	argIdx := 1

	if ip := r.URL.Query().Get("ip"); ip != "" {
		q += " AND client_ip::text = $" + strconv.Itoa(argIdx)
		args = append(args, ip)
		argIdx++
	}
	if path := r.URL.Query().Get("path"); path != "" {
		// F1: REJECT LIKE wildcards (% _) so the param cannot be used to widen
		// the search or exfiltrate log rows the caller should not see.
		if strings.ContainsAny(path, "%_") {
			RespondError(w, http.StatusBadRequest, "INVALID_PATH",
				"path filter must not contain SQL LIKE wildcards (% or _)")
			return
		}
		q += " AND path ILIKE '%' || $" + strconv.Itoa(argIdx) + " || '%' ESCAPE '\\'"
		args = append(args, path)
		argIdx++
	}
	if action := r.URL.Query().Get("action"); action != "" {
		q += " AND action = $" + strconv.Itoa(argIdx)
		args = append(args, action)
		argIdx++
	}
	if min := r.URL.Query().Get("threat_min"); min != "" {
		if v, err := strconv.ParseFloat(min, 64); err == nil {
			q += " AND threat_score >= $" + strconv.Itoa(argIdx)
			args = append(args, v)
			argIdx++
		}
	}
	if max := r.URL.Query().Get("threat_max"); max != "" {
		if v, err := strconv.ParseFloat(max, 64); err == nil {
			q += " AND threat_score <= $" + strconv.Itoa(argIdx)
			args = append(args, v)
			argIdx++
		}
	}

	// Pagination
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage < 1 || perPage > 100 {
		perPage = 50
	}
	offset := (page - 1) * perPage

	q += " ORDER BY timestamp DESC LIMIT $" + strconv.Itoa(argIdx)
	args = append(args, perPage)
	argIdx++
	q += " OFFSET $" + strconv.Itoa(argIdx)
	args = append(args, offset)

	rows, err := h.pool.Query(ctx, q, args...)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "database"))
		return
	}
	defer rows.Close()

	var entries []logEntry
	for rows.Next() {
		var e logEntry
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.ClientIP, &e.Method,
			&e.Host, &e.Path, &e.Query, &e.Headers, &e.UserAgent, &e.Action,
			&e.ThreatScore, &e.AIClassification, &e.ResponseCode,
			&e.ResponseTimeMs, &e.Country); err != nil {
			RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "database"))
			return
		}
		entries = append(entries, e)
	}

	if entries == nil {
		entries = []logEntry{}
	}
	RespondJSON(w, http.StatusOK, entries)
}

// Get handles GET /api/v1/logs/:id
func (h *LogHandler) Get(w http.ResponseWriter, r *http.Request) {
	if h.pool == nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", "database not available")
		return
	}

	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_ID", "invalid log ID")
		return
	}

	ctx := r.Context()
	var e logEntry
	err = h.pool.QueryRow(ctx,
		`SELECT id, timestamp::text, client_ip::text, method, host, path,
		COALESCE(query, ''), headers, COALESCE(user_agent, ''), action,
		COALESCE(threat_score, 0), COALESCE(ai_classification, ''),
		COALESCE(response_code, 0), COALESCE(response_time_ms, 0),
		COALESCE(country, '')
		FROM request_logs WHERE id = $1`, id,
	).Scan(&e.ID, &e.Timestamp, &e.ClientIP, &e.Method,
		&e.Host, &e.Path, &e.Query, &e.Headers, &e.UserAgent, &e.Action,
		&e.ThreatScore, &e.AIClassification, &e.ResponseCode,
		&e.ResponseTimeMs, &e.Country)

	if err != nil {
		RespondError(w, http.StatusNotFound, "NOT_FOUND", "log entry not found")
		return
	}

	RespondJSON(w, http.StatusOK, e)
}
