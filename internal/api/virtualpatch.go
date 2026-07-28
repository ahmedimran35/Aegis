package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/user/waf/internal/audit"
	"github.com/user/waf/internal/auth"
)

// VirtualPatchHandler handles virtual patch API endpoints.
type VirtualPatchHandler struct {
	pool  *pgxpool.Pool
	audit *audit.Logger
}

// NewVirtualPatchHandler creates a virtual patch handler.
func NewVirtualPatchHandler(pool *pgxpool.Pool, auditLog *audit.Logger) *VirtualPatchHandler {
	return &VirtualPatchHandler{pool: pool, audit: auditLog}
}

// List returns virtual patches.
func (h *VirtualPatchHandler) List(w http.ResponseWriter, r *http.Request) {
	rows, err := h.pool.Query(r.Context(),
		`SELECT id, cve_id, name, description, rule_pattern, match_type, action, severity, affected_paths, enabled, created_at
		 FROM virtual_patches ORDER BY created_at DESC`)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "database"))
		return
	}
	defer rows.Close()

	var patches []map[string]interface{}
	for rows.Next() {
		var id int
		var cveID, name, desc, pattern, matchType, action, severity string
		var paths []string
		var enabled bool
		var createdAt interface{}
		if err := rows.Scan(&id, &cveID, &name, &desc, &pattern, &matchType, &action, &severity, &paths, &enabled, &createdAt); err != nil {
			continue
		}
		patches = append(patches, map[string]interface{}{
			"id": id, "cve_id": cveID, "name": name, "description": desc,
			"rule_pattern": pattern, "match_type": matchType, "action": action,
			"severity": severity, "affected_paths": paths, "enabled": enabled,
			"created_at": createdAt,
		})
	}

	RespondJSON(w, http.StatusOK, patches)
}

// Create adds a virtual patch.
func (h *VirtualPatchHandler) Create(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CVEID         string   `json:"cve_id"`
		Name          string   `json:"name"`
		Description   string   `json:"description"`
		RulePattern   string   `json:"rule_pattern"`
		MatchType     string   `json:"match_type"`
		Action        string   `json:"action"`
		Severity      string   `json:"severity"`
		AffectedPaths []string `json:"affected_paths"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}

	if body.CVEID == "" || body.RulePattern == "" {
		RespondError(w, http.StatusBadRequest, "MISSING_FIELDS", "cve_id and rule_pattern required")
		return
	}
	if body.MatchType == "" {
		body.MatchType = "regex"
	}
	if body.Action == "" {
		body.Action = "block"
	}
	if body.Severity == "" {
		body.Severity = "high"
	}

	var id int
	err := h.pool.QueryRow(r.Context(),
		`INSERT INTO virtual_patches (cve_id, name, description, rule_pattern, match_type, action, severity, affected_paths)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
		body.CVEID, body.Name, body.Description, body.RulePattern, body.MatchType, body.Action, body.Severity, body.AffectedPaths).Scan(&id)
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
		h.audit.Log(audit.Entry{UserID: uid, Username: uname, Action: "create", ResourceType: "virtual_patch", ResourceID: strconv.Itoa(id), Details: map[string]string{"cve_id": body.CVEID}, IPAddress: clientIP(r)})
	}
	RespondJSON(w, http.StatusCreated, map[string]interface{}{"id": id})
}

// Delete removes a virtual patch.
func (h *VirtualPatchHandler) Delete(w http.ResponseWriter, r *http.Request) {
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

	_, err = h.pool.Exec(r.Context(), `DELETE FROM virtual_patches WHERE id = $1`, id)
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
		h.audit.Log(audit.Entry{UserID: uid, Username: uname, Action: "delete", ResourceType: "virtual_patch", ResourceID: strconv.Itoa(id), IPAddress: clientIP(r)})
	}

	RespondJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// Toggle handles PUT /api/v1/virtual-patches/{id}/toggle
func (h *VirtualPatchHandler) Toggle(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_ID", "invalid patch ID")
		return
	}

	ctx := r.Context()
	tag, err := h.pool.Exec(ctx,
		`UPDATE virtual_patches SET enabled = NOT enabled WHERE id = $1`, id)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "toggle patch"))
		return
	}
	if tag.RowsAffected() == 0 {
		RespondError(w, http.StatusNotFound, "NOT_FOUND", "patch not found")
		return
	}

	if h.audit != nil {
		var uid int
		var uname string
		if c := auth.ClaimsFromContext(r.Context()); c != nil {
			uid, uname = c.UserID, c.Username
		}
		h.audit.Log(audit.Entry{UserID: uid, Username: uname, Action: "toggle", ResourceType: "virtual_patch", ResourceID: strconv.Itoa(id), IPAddress: clientIP(r)})
	}
	RespondJSON(w, http.StatusOK, map[string]bool{"toggled": true})
}
