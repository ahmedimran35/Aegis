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

// APISchemaHandler handles API schema CRUD endpoints.
type APISchemaHandler struct {
	pool  *pgxpool.Pool
	audit *audit.Logger
}

// NewAPISchemaHandler creates an API schema handler.
func NewAPISchemaHandler(pool *pgxpool.Pool, auditLog *audit.Logger) *APISchemaHandler {
	return &APISchemaHandler{pool: pool, audit: auditLog}
}

type apiSchemaRow struct {
	ID        int             `json:"id"`
	Name      string          `json:"name"`
	BasePath  string          `json:"base_path"`
	Spec      json.RawMessage `json:"spec"`
	Enabled   bool            `json:"enabled"`
	CreatedAt string          `json:"created_at"`
}

// List handles GET /api/v1/api-schemas
func (h *APISchemaHandler) List(w http.ResponseWriter, r *http.Request) {
	rows, err := h.pool.Query(r.Context(),
		`SELECT id, name, base_path, spec, enabled, created_at::text
		 FROM api_schemas ORDER BY id`)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "list schemas"))
		return
	}
	defer rows.Close()

	var schemas []apiSchemaRow
	for rows.Next() {
		var s apiSchemaRow
		if err := rows.Scan(&s.ID, &s.Name, &s.BasePath, &s.Spec, &s.Enabled, &s.CreatedAt); err != nil {
			continue
		}
		schemas = append(schemas, s)
	}
	if schemas == nil {
		schemas = []apiSchemaRow{}
	}
	RespondJSON(w, http.StatusOK, schemas)
}

// Create handles POST /api/v1/api-schemas
func (h *APISchemaHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string          `json:"name"`
		BasePath string          `json:"base_path"`
		Spec     json.RawMessage `json:"spec"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}

	if req.Name == "" || req.BasePath == "" || len(req.Spec) == 0 {
		RespondError(w, http.StatusBadRequest, "MISSING_FIELDS", "name, base_path, and spec required")
		return
	}

	var schema apiSchemaRow
	err := h.pool.QueryRow(r.Context(),
		`INSERT INTO api_schemas (name, base_path, spec)
		 VALUES ($1, $2, $3)
		 RETURNING id, name, base_path, spec, enabled, created_at::text`,
		req.Name, req.BasePath, req.Spec,
	).Scan(&schema.ID, &schema.Name, &schema.BasePath, &schema.Spec, &schema.Enabled, &schema.CreatedAt)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "create schema"))
		return
	}

	if h.audit != nil {
		var uid int
		var uname string
		if c := auth.ClaimsFromContext(r.Context()); c != nil {
			uid, uname = c.UserID, c.Username
		}
		h.audit.Log(audit.Entry{UserID: uid, Username: uname, Action: "create", ResourceType: "api_schema", ResourceID: strconv.Itoa(schema.ID), Details: map[string]string{"name": schema.Name}, IPAddress: clientIP(r)})
	}
	RespondJSON(w, http.StatusCreated, schema)
}

// Delete handles DELETE /api/v1/api-schemas/{id}
func (h *APISchemaHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_ID", "invalid schema ID")
		return
	}

	tag, err := h.pool.Exec(r.Context(), `DELETE FROM api_schemas WHERE id = $1`, id)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "delete schema"))
		return
	}
	if tag.RowsAffected() == 0 {
		RespondError(w, http.StatusNotFound, "NOT_FOUND", "schema not found")
		return
	}

	if h.audit != nil {
		var uid int
		var uname string
		if c := auth.ClaimsFromContext(r.Context()); c != nil {
			uid, uname = c.UserID, c.Username
		}
		h.audit.Log(audit.Entry{UserID: uid, Username: uname, Action: "delete", ResourceType: "api_schema", ResourceID: strconv.Itoa(id), IPAddress: clientIP(r)})
	}
	RespondJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}
