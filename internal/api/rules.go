package api

import (
	"encoding/json"
	"net"
	"net/http"
	"regexp"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/user/waf/internal/audit"
	"github.com/user/waf/internal/auth"
	wafmw "github.com/user/waf/internal/middleware"
	"github.com/user/waf/internal/rules"
)

// RuleHandler handles rule CRUD operations.
type RuleHandler struct {
	pool  *pgxpool.Pool
	audit *audit.Logger
}

// NewRuleHandler creates a new rule handler.
func NewRuleHandler(pool *pgxpool.Pool, auditLog *audit.Logger) *RuleHandler {
	return &RuleHandler{pool: pool, audit: auditLog}
}

// ruleRow matches the rules table schema.
type ruleRow struct {
	ID          int     `json:"id"`
	Name        string  `json:"name"`
	Pattern     string  `json:"pattern"`
	MatchType   string  `json:"match_type"`
	Action      string  `json:"action"`
	Severity    string  `json:"severity"`
	Priority    int     `json:"priority"`
	Enabled     bool    `json:"enabled"`
	HitCount    int64   `json:"hit_count"`
	Source      string  `json:"source"`
	Description string  `json:"description"`
	CreatedAt   string  `json:"created_at"`
	UpdatedAt   string  `json:"updated_at"`
}

// createRuleRequest is the payload for creating a rule.
type createRuleRequest struct {
	Name        string `json:"name"`
	Pattern     string `json:"pattern"`
	MatchType   string `json:"match_type"`
	Action      string `json:"action"`
	Severity    string `json:"severity"`
	Priority    int    `json:"priority"`
	Description string `json:"description"`
}

// List handles GET /api/v1/rules
func (h *RuleHandler) List(w http.ResponseWriter, r *http.Request) {
	if h.pool == nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", "database not available")
		return
	}

	ctx := r.Context()

	// Parse optional filters
	q := `SELECT id, name, pattern, match_type, action, severity, priority, enabled, hit_count, source,
		COALESCE(description, ''), created_at::text, updated_at::text FROM rules WHERE 1=1`
	args := []interface{}{}
	argIdx := 1

	if status := r.URL.Query().Get("status"); status == "enabled" {
		q += " AND enabled = true"
	} else if status == "disabled" {
		q += " AND enabled = false"
	}
	if severity := r.URL.Query().Get("severity"); severity != "" {
		q += " AND severity = $" + strconv.Itoa(argIdx)
		args = append(args, severity)
		argIdx++
	}
	if source := r.URL.Query().Get("source"); source != "" {
		q += " AND source = $" + strconv.Itoa(argIdx)
		args = append(args, source)
		argIdx++
	}

	q += " ORDER BY priority ASC, id ASC"

	rows, err := h.pool.Query(ctx, q, args...)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "database"))
		return
	}
	defer rows.Close()

	var rules []ruleRow
	for rows.Next() {
		var r ruleRow
		if err := rows.Scan(&r.ID, &r.Name, &r.Pattern, &r.MatchType, &r.Action,
			&r.Severity, &r.Priority, &r.Enabled, &r.HitCount, &r.Source,
			&r.Description, &r.CreatedAt, &r.UpdatedAt); err != nil {
			RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "database"))
			return
		}
		rules = append(rules, r)
	}

	if rules == nil {
		rules = []ruleRow{}
	}
	RespondJSON(w, http.StatusOK, rules)
}

// Create handles POST /api/v1/rules
func (h *RuleHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req createRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if req.Name == "" || req.Pattern == "" || req.MatchType == "" || req.Action == "" || req.Severity == "" {
		RespondError(w, http.StatusBadRequest, "MISSING_FIELDS", "name, pattern, match_type, action, severity are required")
		return
	}

	// P-FIX (F-4): Reject patterns with ReDoS risk at the API layer
	// rather than only at engine load. Previously, admin-submitted
	// patterns were persisted even when HasReDoSRisk rejected them,
	// leading to "phantom" rules in the DB. Now we reject at write
	// time so the DB never holds a ReDoS bomb.
	if req.MatchType == "regex" {
		if err := rules.HasReDoSRisk(req.Pattern); err != nil {
			RespondError(w, http.StatusBadRequest, "REDOS_RISK",
				"pattern rejected: "+err.Error())
			return
		}
		if _, err := regexp.Compile(req.Pattern); err != nil {
			RespondError(w, http.StatusBadRequest, "INVALID_REGEX",
				"pattern does not compile: "+err.Error())
			return
		}
	}

	if req.Priority == 0 {
		req.Priority = 100
	}

	ctx := r.Context()
	var rule ruleRow
	err := h.pool.QueryRow(ctx,
		`INSERT INTO rules (name, pattern, match_type, action, severity, priority, description)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 RETURNING id, name, pattern, match_type, action, severity, priority, enabled, hit_count, source,
		           COALESCE(description, ''), created_at::text, updated_at::text`,
		req.Name, req.Pattern, req.MatchType, req.Action, req.Severity, req.Priority, req.Description,
	).Scan(&rule.ID, &rule.Name, &rule.Pattern, &rule.MatchType, &rule.Action,
		&rule.Severity, &rule.Priority, &rule.Enabled, &rule.HitCount, &rule.Source,
		&rule.Description, &rule.CreatedAt, &rule.UpdatedAt)

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
		h.audit.LogRuleChange(uid, uname, "create", rule.ID, map[string]string{"name": rule.Name}, clientIP(r))
	}
	RespondJSON(w, http.StatusCreated, rule)
}

// Get handles GET /api/v1/rules/{id}
func (h *RuleHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_ID", "invalid rule ID")
		return
	}

	ctx := r.Context()
	var rule ruleRow
	err = h.pool.QueryRow(ctx,
		`SELECT id, name, pattern, match_type, action, severity, priority, enabled, hit_count, source,
		COALESCE(description, ''), created_at::text, updated_at::text FROM rules WHERE id = $1`, id,
	).Scan(&rule.ID, &rule.Name, &rule.Pattern, &rule.MatchType, &rule.Action,
		&rule.Severity, &rule.Priority, &rule.Enabled, &rule.HitCount, &rule.Source,
		&rule.Description, &rule.CreatedAt, &rule.UpdatedAt)

	if err != nil {
		RespondError(w, http.StatusNotFound, "NOT_FOUND", "rule not found")
		return
	}

	RespondJSON(w, http.StatusOK, rule)
}

// Update handles PUT /api/v1/rules/{id}
func (h *RuleHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_ID", "invalid rule ID")
		return
	}

	var req createRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	ctx := r.Context()
	var rule ruleRow
	err = h.pool.QueryRow(ctx,
		`UPDATE rules SET name=$2, pattern=$3, match_type=$4, action=$5, severity=$6, priority=$7,
		 description=$8, updated_at=NOW()
		 WHERE id = $1
		 RETURNING id, name, pattern, match_type, action, severity, priority, enabled, hit_count, source,
		           COALESCE(description, ''), created_at::text, updated_at::text`,
		id, req.Name, req.Pattern, req.MatchType, req.Action, req.Severity, req.Priority, req.Description,
	).Scan(&rule.ID, &rule.Name, &rule.Pattern, &rule.MatchType, &rule.Action,
		&rule.Severity, &rule.Priority, &rule.Enabled, &rule.HitCount, &rule.Source,
		&rule.Description, &rule.CreatedAt, &rule.UpdatedAt)

	if err != nil {
		RespondError(w, http.StatusNotFound, "NOT_FOUND", "rule not found")
		return
	}

	if h.audit != nil {
		var uid int
		var uname string
		if c := auth.ClaimsFromContext(r.Context()); c != nil {
			uid, uname = c.UserID, c.Username
		}
		h.audit.LogRuleChange(uid, uname, "update", rule.ID, map[string]string{"name": rule.Name}, clientIP(r))
	}
	RespondJSON(w, http.StatusOK, rule)
}

// Delete handles DELETE /api/v1/rules/{id}
func (h *RuleHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_ID", "invalid rule ID")
		return
	}

	ctx := r.Context()
	tag, err := h.pool.Exec(ctx, `DELETE FROM rules WHERE id = $1`, id)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "database"))
		return
	}
	if tag.RowsAffected() == 0 {
		RespondError(w, http.StatusNotFound, "NOT_FOUND", "rule not found")
		return
	}

	if h.audit != nil {
		var uid int
		var uname string
		if c := auth.ClaimsFromContext(r.Context()); c != nil {
			uid, uname = c.UserID, c.Username
		}
		h.audit.LogRuleChange(uid, uname, "delete", id, nil, clientIP(r))
	}
	RespondJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

// Toggle handles PUT /api/v1/rules/{id}/toggle
func (h *RuleHandler) Toggle(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_ID", "invalid rule ID")
		return
	}

	ctx := r.Context()
	var rule ruleRow
	err = h.pool.QueryRow(ctx,
		`UPDATE rules SET enabled = NOT enabled, updated_at = NOW()
		 WHERE id = $1
		 RETURNING id, name, pattern, match_type, action, severity, priority, enabled, hit_count, source,
		           COALESCE(description, ''), created_at::text, updated_at::text`, id,
	).Scan(&rule.ID, &rule.Name, &rule.Pattern, &rule.MatchType, &rule.Action,
		&rule.Severity, &rule.Priority, &rule.Enabled, &rule.HitCount, &rule.Source,
		&rule.Description, &rule.CreatedAt, &rule.UpdatedAt)

	if err != nil {
		RespondError(w, http.StatusNotFound, "NOT_FOUND", "rule not found")
		return
	}

	if h.audit != nil {
		var uid int
		var uname string
		if c := auth.ClaimsFromContext(r.Context()); c != nil {
			uid, uname = c.UserID, c.Username
		}
		h.audit.LogRuleChange(uid, uname, "toggle", rule.ID, map[string]bool{"enabled": rule.Enabled}, clientIP(r))
	}
	RespondJSON(w, http.StatusOK, rule)
}

// Stats handles GET /api/v1/rules/{id}/stats
func (h *RuleHandler) Stats(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_ID", "invalid rule ID")
		return
	}

	ctx := r.Context()
	var hitCount int64
	err = h.pool.QueryRow(ctx, `SELECT hit_count FROM rules WHERE id = $1`, id).Scan(&hitCount)
	if err != nil {
		RespondError(w, http.StatusNotFound, "NOT_FOUND", "rule not found")
		return
	}

	RespondJSON(w, http.StatusOK, map[string]interface{}{
		"rule_id":   id,
		"hit_count": hitCount,
	})
}

// clientIP extracts the client IP from the request for audit logging.
func clientIP(r *http.Request) net.IP {
	return wafmw.ExtractClientIP(r)
}
