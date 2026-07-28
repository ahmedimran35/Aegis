package api

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/user/waf/internal/audit"
	"github.com/user/waf/internal/auth"
)

// AllowlistHandler handles allowlist CRUD endpoints.
type AllowlistHandler struct {
	pool  *pgxpool.Pool
	audit *audit.Logger
}

// NewAllowlistHandler creates an allowlist handler.
func NewAllowlistHandler(pool *pgxpool.Pool, auditLog *audit.Logger) *AllowlistHandler {
	return &AllowlistHandler{pool: pool, audit: auditLog}
}

type allowlistRow struct {
	ID          int    `json:"id"`
	RuleType    string `json:"rule_type"`
	Pattern     string `json:"pattern"`
	Description string `json:"description"`
	Priority    int    `json:"priority"`
	Enabled     bool   `json:"enabled"`
	CreatedAt   string `json:"created_at"`
}

// List handles GET /api/v1/allowlist
func (h *AllowlistHandler) List(w http.ResponseWriter, r *http.Request) {
	rows, err := h.pool.Query(r.Context(),
		`SELECT id, rule_type, pattern, COALESCE(description, ''), priority, enabled, created_at::text
		 FROM allowlist_rules ORDER BY priority ASC, id ASC`)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "list allowlist"))
		return
	}
	defer rows.Close()

	var rules []allowlistRow
	for rows.Next() {
		var r allowlistRow
		if err := rows.Scan(&r.ID, &r.RuleType, &r.Pattern, &r.Description, &r.Priority, &r.Enabled, &r.CreatedAt); err != nil {
			continue
		}
		rules = append(rules, r)
	}
	if rules == nil {
		rules = []allowlistRow{}
	}
	RespondJSON(w, http.StatusOK, rules)
}

// Create handles POST /api/v1/allowlist
func (h *AllowlistHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RuleType    string `json:"rule_type"`
		Pattern     string `json:"pattern"`
		Description string `json:"description"`
		Priority    int    `json:"priority"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}

	if req.RuleType == "" || req.Pattern == "" {
		RespondError(w, http.StatusBadRequest, "MISSING_FIELDS", "rule_type and pattern required")
		return
	}

	// Validate rule_type
	validTypes := map[string]bool{"ip": true, "cidr": true, "path": true, "user_agent": true}
	if !validTypes[req.RuleType] {
		RespondError(w, http.StatusBadRequest, "INVALID_TYPE", "rule_type must be ip, cidr, path, or user_agent")
		return
	}

	// Validate IP/CIDR format for ip/cidr types
	if req.RuleType == "ip" || req.RuleType == "cidr" {
		if net.ParseIP(req.Pattern) == nil {
			if _, _, err := net.ParseCIDR(req.Pattern); err != nil {
				RespondError(w, http.StatusBadRequest, "INVALID_PATTERN", "invalid IP or CIDR pattern")
				return
			}
		}
	}

	if req.Priority == 0 {
		req.Priority = 100
	}

	var rule allowlistRow
	err := h.pool.QueryRow(r.Context(),
		`INSERT INTO allowlist_rules (rule_type, pattern, description, priority)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, rule_type, pattern, COALESCE(description, ''), priority, enabled, created_at::text`,
		req.RuleType, req.Pattern, req.Description, req.Priority,
	).Scan(&rule.ID, &rule.RuleType, &rule.Pattern, &rule.Description, &rule.Priority, &rule.Enabled, &rule.CreatedAt)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "create allowlist rule"))
		return
	}

	if h.audit != nil {
		var uid int
		var uname string
		if c := auth.ClaimsFromContext(r.Context()); c != nil {
			uid, uname = c.UserID, c.Username
		}
		h.audit.Log(audit.Entry{UserID: uid, Username: uname, Action: "create", ResourceType: "allowlist", ResourceID: strconv.Itoa(rule.ID), Details: map[string]string{"rule_type": rule.RuleType, "pattern": rule.Pattern}, IPAddress: clientIP(r)})
	}
	RespondJSON(w, http.StatusCreated, rule)
}

// Delete handles DELETE /api/v1/allowlist/{id}
func (h *AllowlistHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_ID", "invalid allowlist rule ID")
		return
	}

	tag, err := h.pool.Exec(r.Context(), `DELETE FROM allowlist_rules WHERE id = $1`, id)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "delete allowlist rule"))
		return
	}
	if tag.RowsAffected() == 0 {
		RespondError(w, http.StatusNotFound, "NOT_FOUND", "allowlist rule not found")
		return
	}

	if h.audit != nil {
		var uid int
		var uname string
		if c := auth.ClaimsFromContext(r.Context()); c != nil {
			uid, uname = c.UserID, c.Username
		}
		h.audit.Log(audit.Entry{UserID: uid, Username: uname, Action: "delete", ResourceType: "allowlist", ResourceID: strconv.Itoa(id), IPAddress: clientIP(r)})
	}
	RespondJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}
