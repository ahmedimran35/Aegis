package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/user/waf/internal/audit"
	wafmw "github.com/user/waf/internal/middleware"
)

// CanaryHandler manages canary tokens and shows recent canary hits.
type CanaryHandler struct {
	pool    *pgxpool.Pool
	audit   *audit.Logger
	canary  *wafmw.Canary
}

func NewCanaryHandler(pool *pgxpool.Pool, auditLog *audit.Logger, c *wafmw.Canary) *CanaryHandler {
	return &CanaryHandler{pool: pool, audit: auditLog, canary: c}
}

type canaryToken struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	TokenValue string `json:"token_value"`
	Kind       string `json:"kind"`
	Placement  string `json:"placement"`
	Enabled    bool   `json:"enabled"`
	CreatedAt  string `json:"created_at"`
}

type canaryHit struct {
	ID            int    `json:"id"`
	TokenID       int    `json:"token_id"`
	TokenName     string `json:"token_name"`
	IP            string `json:"ip"`
	Method        string `json:"method"`
	Path          string `json:"path"`
	UserAgent     string `json:"user_agent"`
	MatchedOn     string `json:"matched_on"`
	Excerpt       string `json:"excerpt"`
	CreatedAt     string `json:"created_at"`
}

type createCanaryRequest struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Placement string `json:"placement"`
}

// List handles GET /api/v1/canary/tokens
func (h *CanaryHandler) ListTokens(w http.ResponseWriter, r *http.Request) {
	rows, err := h.pool.Query(r.Context(),
		`SELECT id, name, token_value, kind, placement, enabled, created_at::text
		 FROM canary_tokens ORDER BY id DESC LIMIT 200`)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
		return
	}
	defer rows.Close()
	out := []canaryToken{}
	for rows.Next() {
		var t canaryToken
		if err := rows.Scan(&t.ID, &t.Name, &t.TokenValue, &t.Kind, &t.Placement, &t.Enabled, &t.CreatedAt); err != nil {
			continue
		}
		out = append(out, t)
	}
	RespondJSON(w, http.StatusOK, out)
}

// Create handles POST /api/v1/canary/tokens
func (h *CanaryHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req createCanaryRequest
	if err := readJSON(r, &req); err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_JSON", err.Error())
		return
	}
	if req.Name == "" || req.Kind == "" {
		RespondError(w, http.StatusBadRequest, "MISSING_FIELDS", "name and kind are required")
		return
	}
	if req.Kind != "form_field" && req.Kind != "url" && req.Kind != "cookie" && req.Kind != "header" {
		RespondError(w, http.StatusBadRequest, "INVALID_KIND", "kind must be one of: form_field, url, cookie, header")
		return
	}
	tok := wafmw.GenerateToken()
	var t canaryToken
	err := h.pool.QueryRow(r.Context(),
		`INSERT INTO canary_tokens (name, token_value, kind, placement, enabled)
		 VALUES ($1, $2, $3, $4, true)
		 RETURNING id, name, token_value, kind, placement, enabled, created_at::text`,
		req.Name, tok, req.Kind, req.Placement,
	).Scan(&t.ID, &t.Name, &t.TokenValue, &t.Kind, &t.Placement, &t.Enabled, &t.CreatedAt)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
		return
	}
	// Refresh in-memory cache so the canary takes effect immediately
	if h.canary != nil {
		_ = h.canary.Refresh(r.Context())
	}
	RespondJSON(w, http.StatusCreated, t)
}

// Delete handles DELETE /api/v1/canary/tokens/{id}
func (h *CanaryHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_ID", "invalid id")
		return
	}
	tag, err := h.pool.Exec(r.Context(), `DELETE FROM canary_tokens WHERE id = $1`, id)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		RespondError(w, http.StatusNotFound, "NOT_FOUND", "canary token not found")
		return
	}
	if h.canary != nil {
		_ = h.canary.Refresh(r.Context())
	}
	RespondJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

// Toggle handles PATCH /api/v1/canary/tokens/{id}/toggle
func (h *CanaryHandler) Toggle(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_ID", "invalid id")
		return
	}
	var enabled bool
	err = h.pool.QueryRow(r.Context(),
		`UPDATE canary_tokens SET enabled = NOT enabled WHERE id = $1 RETURNING enabled`,
		id,
	).Scan(&enabled)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
		return
	}
	if h.canary != nil {
		_ = h.canary.Refresh(r.Context())
	}
	RespondJSON(w, http.StatusOK, map[string]any{"id": id, "enabled": enabled})
}

// Hits handles GET /api/v1/canary/hits
func (h *CanaryHandler) Hits(w http.ResponseWriter, r *http.Request) {
	rows, err := h.pool.Query(r.Context(),
		`SELECT ch.id, ch.token_id, COALESCE(t.name, ''),
		        COALESCE(ch.ip::text, ''), COALESCE(ch.method, ''), COALESCE(ch.path, ''),
		        COALESCE(ch.user_agent, ''), ch.matched_on, COALESCE(ch.request_excerpt, ''),
		        ch.created_at::text
		 FROM canary_hits ch
		 LEFT JOIN canary_tokens t ON t.id = ch.token_id
		 ORDER BY ch.created_at DESC LIMIT 200`)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
		return
	}
	defer rows.Close()
	out := []canaryHit{}
	for rows.Next() {
		var h2 canaryHit
		if err := rows.Scan(&h2.ID, &h2.TokenID, &h2.TokenName, &h2.IP, &h2.Method, &h2.Path, &h2.UserAgent, &h2.MatchedOn, &h2.Excerpt, &h2.CreatedAt); err != nil {
			continue
		}
		out = append(out, h2)
	}
	RespondJSON(w, http.StatusOK, out)
}

// helpers
func readJSON(r *http.Request, dst any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(dst)
}
