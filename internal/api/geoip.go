package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/user/waf/internal/audit"
	"github.com/user/waf/internal/auth"
)

// GeoIPHandler handles GeoIP rule management.
type GeoIPHandler struct {
	pool interface {
		QueryRow(ctx interface{}, sql string, args ...interface{}) interface{ Scan(dest ...interface{}) error }
		Query(ctx interface{}, sql string, args ...interface{}) (interface{ Close(); Next() bool; Scan(dest ...interface{}) error }, error)
	}
}

// NewGeoIPHandler creates a GeoIP handler.
func NewGeoIPHandler(pool *pgxpool.Pool) *GeoIPHandler {
	return &GeoIPHandler{}
}

// GeoIPHandler2 handles GeoIP API endpoints.
type GeoIPHandler2 struct {
	pool  *pgxpool.Pool
	audit *audit.Logger
}

// NewGeoIPHandler2 creates a GeoIP handler.
func NewGeoIPHandler2(pool *pgxpool.Pool, auditLog *audit.Logger) *GeoIPHandler2 {
	return &GeoIPHandler2{pool: pool, audit: auditLog}
}

// List returns GeoIP rules.
func (h *GeoIPHandler2) List(w http.ResponseWriter, r *http.Request) {
	rows, err := h.pool.Query(r.Context(),
		`SELECT id, country_code, action, reason, enabled, created_at FROM geoip_rules ORDER BY country_code`)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "database"))
		return
	}
	defer rows.Close()

	var rules []map[string]interface{}
	for rows.Next() {
		var id int
		var cc, action string
		var reason *string
		var enabled bool
		var createdAt interface{}
		if err := rows.Scan(&id, &cc, &action, &reason, &enabled, &createdAt); err != nil {
			continue
		}
		rule := map[string]interface{}{
			"id":           id,
			"country_code": cc,
			"action":       action,
			"enabled":      enabled,
			"created_at":   createdAt,
		}
		if reason != nil {
			rule["reason"] = *reason
		}
		rules = append(rules, rule)
	}

	RespondJSON(w, http.StatusOK, rules)
}

// Create adds a GeoIP rule.
func (h *GeoIPHandler2) Create(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CountryCode string `json:"country_code"`
		Action      string `json:"action"`
		Reason      string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}

	if body.CountryCode == "" || body.Action == "" {
		RespondError(w, http.StatusBadRequest, "MISSING_FIELDS", "country_code and action required")
		return
	}

	var id int
	err := h.pool.QueryRow(r.Context(),
		`INSERT INTO geoip_rules (country_code, action, reason) VALUES ($1, $2, $3) RETURNING id`,
		body.CountryCode, body.Action, body.Reason).Scan(&id)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "database"))
		return
	}

	if h.audit != nil {
		var uid int
		var uname string
		if c := auth.ClaimsFromContext(r.Context()); c != nil {
			uid, uname = c.UserID, c.Username
		}
		h.audit.Log(audit.Entry{UserID: uid, Username: uname, Action: "create", ResourceType: "geoip", ResourceID: strconv.Itoa(id), Details: map[string]string{"country_code": body.CountryCode, "action": body.Action}, IPAddress: clientIP(r)})
	}
	RespondJSON(w, http.StatusCreated, map[string]interface{}{"id": id})
}

// Delete removes a GeoIP rule.
func (h *GeoIPHandler2) Delete(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		RespondError(w, http.StatusBadRequest, "MISSING_ID", "id required")
		return
	}
	id, err := strconv.Atoi(idStr)
	if err != nil || id <= 0 {
		RespondError(w, http.StatusBadRequest, "INVALID_ID", "id must be a positive integer")
		return
	}

	_, err = h.pool.Exec(r.Context(), `DELETE FROM geoip_rules WHERE id = $1`, id)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "database"))
		return
	}

	if h.audit != nil {
		var uid int
		var uname string
		if c := auth.ClaimsFromContext(r.Context()); c != nil {
			uid, uname = c.UserID, c.Username
		}
		h.audit.Log(audit.Entry{UserID: uid, Username: uname, Action: "delete", ResourceType: "geoip", ResourceID: strconv.Itoa(id), IPAddress: clientIP(r)})
	}

	RespondJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
