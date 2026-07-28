package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/user/waf/internal/middleware"
)

// JA3Handler handles TLS fingerprint API endpoints.
type JA3Handler struct {
	checker *middleware.JA3Checker
	pool    *pgxpool.Pool
}

// NewJA3Handler creates a JA3 handler.
func NewJA3Handler(checker *middleware.JA3Checker, pool *pgxpool.Pool) *JA3Handler {
	return &JA3Handler{checker: checker, pool: pool}
}

// SetReputation updates the reputation of a TLS fingerprint.
func (h *JA3Handler) SetReputation(w http.ResponseWriter, r *http.Request) {
	ja3Hash := chi.URLParam(r, "hash")

	var body struct {
		Reputation string `json:"reputation"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}

	if body.Reputation == "" {
		RespondError(w, http.StatusBadRequest, "MISSING_FIELDS", "reputation required")
		return
	}

	if err := h.checker.SetReputation(ja3Hash, body.Reputation); err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "database"))
		return
	}

	RespondJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

// GetReputation returns the reputation of a TLS fingerprint.
func (h *JA3Handler) GetReputation(w http.ResponseWriter, r *http.Request) {
	ja3Hash := chi.URLParam(r, "hash")
	reputation := h.checker.GetReputation(ja3Hash)
	RespondJSON(w, http.StatusOK, map[string]string{
		"ja3_hash":   ja3Hash,
		"reputation": reputation,
	})
}

// ListFingerprints returns all TLS fingerprints from DB.
func (h *JA3Handler) ListFingerprints(w http.ResponseWriter, r *http.Request) {
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
	if err := h.pool.QueryRow(r.Context(), `SELECT COUNT(*) FROM tls_fingerprints`).Scan(&total); err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "ja3 count"))
		return
	}

	rows, err := h.pool.Query(r.Context(),
		`SELECT id, ja3_hash, client_ip::text, user_agent, first_seen, last_seen, request_count, reputation
		 FROM tls_fingerprints ORDER BY last_seen DESC LIMIT $1 OFFSET $2`, perPage, offset)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "database"))
		return
	}
	defer rows.Close()

	var fps []map[string]interface{}
	for rows.Next() {
		var id int
		var ja3, ip, ua, reputation string
		var firstSeen, lastSeen interface{}
		var count int
		if err := rows.Scan(&id, &ja3, &ip, &ua, &firstSeen, &lastSeen, &count, &reputation); err != nil {
			continue
		}
		fps = append(fps, map[string]interface{}{
			"id": id, "ja3_hash": ja3, "client_ip": ip, "user_agent": ua,
			"first_seen": firstSeen, "last_seen": lastSeen,
			"request_count": count, "reputation": reputation,
		})
	}

	RespondJSONWithMeta(w, http.StatusOK, fps, &Meta{
		Page: page, PerPage: perPage, Total: total,
	})
}
