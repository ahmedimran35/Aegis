package api

import (
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SessionHandler handles session API endpoints.
type SessionHandler struct {
	pool *pgxpool.Pool
}

// NewSessionHandler creates a session handler.
func NewSessionHandler(pool *pgxpool.Pool) *SessionHandler {
	return &SessionHandler{pool: pool}
}

// List returns active sessions.
func (h *SessionHandler) List(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage < 1 || perPage > 100 {
		perPage = 50
	}
	offset := (page - 1) * perPage

	var total int
	if err := h.pool.QueryRow(r.Context(), `SELECT COUNT(*) FROM sessions`).Scan(&total); err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "session count"))
		return
	}

	rows, err := h.pool.Query(r.Context(),
		`SELECT id, client_ip::text, user_agent, fingerprint, first_seen, last_seen, request_count, blocked_count, country
		 FROM sessions ORDER BY last_seen DESC LIMIT $1 OFFSET $2`, perPage, offset)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "database"))
		return
	}
	defer rows.Close()

	var sessions []map[string]interface{}
	for rows.Next() {
		var id, ip, ua string
		var fp *string
		var firstSeen, lastSeen interface{}
		var reqCount, blockedCount int
		var country *string

		if err := rows.Scan(&id, &ip, &ua, &fp, &firstSeen, &lastSeen, &reqCount, &blockedCount, &country); err != nil {
			continue
		}

		session := map[string]interface{}{
			"id":             id,
			"client_ip":      ip,
			"user_agent":     ua,
			"first_seen":     firstSeen,
			"last_seen":      lastSeen,
			"request_count":  reqCount,
			"blocked_count":  blockedCount,
		}
		if fp != nil {
			session["fingerprint"] = *fp
		}
		if country != nil {
			session["country"] = *country
		}
		sessions = append(sessions, session)
	}

	RespondJSONWithMeta(w, http.StatusOK, sessions, &Meta{
		Page:    page,
		PerPage: perPage,
		Total:   total,
	})
}

// Get returns a single session.
func (h *SessionHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		RespondError(w, http.StatusBadRequest, "MISSING_ID", "session id required")
		return
	}

	var ip, ua string
	var fp *string
	var firstSeen, lastSeen interface{}
	var reqCount, blockedCount int
	var country *string

	err := h.pool.QueryRow(r.Context(),
		`SELECT client_ip::text, user_agent, fingerprint, first_seen, last_seen, request_count, blocked_count, country
		 FROM sessions WHERE id = $1`, id).Scan(&ip, &ua, &fp, &firstSeen, &lastSeen, &reqCount, &blockedCount, &country)
	if err != nil {
		RespondError(w, http.StatusNotFound, "NOT_FOUND", "session not found")
		return
	}

	session := map[string]interface{}{
		"id":             id,
		"client_ip":      ip,
		"user_agent":     ua,
		"first_seen":     firstSeen,
		"last_seen":      lastSeen,
		"request_count":  reqCount,
		"blocked_count":  blockedCount,
	}
	if fp != nil {
		session["fingerprint"] = *fp
	}
	if country != nil {
		session["country"] = *country
	}

	RespondJSON(w, http.StatusOK, session)
}
