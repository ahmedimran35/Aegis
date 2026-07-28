package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/user/waf/internal/auth"
	wafmw "github.com/user/waf/internal/middleware"
	"github.com/user/waf/internal/rules"
)

// maxReasonLen caps the size of the human-written reason/payload field
// in feedback endpoints. F40: a malicious or buggy client could otherwise
// allocate gigabytes of Postgres storage in a single POST.
const maxReasonLen = 1024

// hasRegexMeta returns true if s contains any regex metacharacter. Used
// by the auto-feedback endpoint to reject patterns that the rule engine
// would otherwise compile as regex (which would let a malicious editor
// inject a ReDoS rule).
func hasRegexMeta(s string) bool {
	for _, r := range s {
		switch r {
		case '\\', '.', '+', '*', '?', '(', ')', '[', ']', '{', '}', '|',
			'^', '$', '-':
			return true
		}
	}
	return false
}

// FeedbackHandler handles false-positive feedback endpoints.
type FeedbackHandler struct {
	pool        *pgxpool.Pool
	policyTuner *wafmw.PolicyTuner
	ruleEngine  Reloader
}

// Reloader is the subset of rules.Engine used by FeedbackHandler.
type Reloader interface {
	Reload()
}

// NewFeedbackHandler creates a new feedback handler.
func NewFeedbackHandler(pool *pgxpool.Pool, policyTuner *wafmw.PolicyTuner, ruleEngine Reloader) *FeedbackHandler {
	return &FeedbackHandler{pool: pool, policyTuner: policyTuner, ruleEngine: ruleEngine}
}

type falsePositive struct {
	ID         int    `json:"id"`
	LogID      int    `json:"log_id"`
	RuleID     int    `json:"rule_id"`
	Reason     string `json:"reason"`
	ReviewedBy int    `json:"reviewed_by"`
	Username   string `json:"username"`
	CreatedAt  string `json:"created_at"`
}

// Create handles POST /api/v1/logs/{id}/false-positive.
//
// P-FIX (L-6): wrap the handler body in defer recover() so a panic in
// this code path (e.g. due to a downstream driver bug) cannot bring
// down the whole API process.
func (h *FeedbackHandler) Create(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("feedback.Create: panic recovered: %v", rec)
		}
	}()
	if h.pool == nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", "database not available")
		return
	}

	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		RespondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
		return
	}

	logID, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_ID", "invalid log ID")
		return
	}

	var req struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_BODY", "invalid JSON body")
		return
	}
	// F40: cap the reason to avoid unbounded Postgres writes.
	if len(req.Reason) > maxReasonLen {
		req.Reason = req.Reason[:maxReasonLen]
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Look up rule_id and path from the log entry
	var ruleID int
	var logPath string
	err = h.pool.QueryRow(ctx,
		`SELECT COALESCE(rule_id, 0), path FROM request_logs WHERE id = $1`, logID,
	).Scan(&ruleID, &logPath)
	if err != nil {
		RespondError(w, http.StatusNotFound, "NOT_FOUND", "log entry not found")
		return
	}

	var fpID int
	err = h.pool.QueryRow(ctx,
		`INSERT INTO false_positives (log_id, rule_id, reason, reviewed_by)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		logID, ruleID, req.Reason, claims.UserID,
	).Scan(&fpID)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "insert false positive"))
		return
	}
	if h.policyTuner != nil {
		h.policyTuner.RecordFP(logPath)
	}

	RespondJSON(w, http.StatusCreated, map[string]interface{}{
		"id":      fpID,
		"log_id":  logID,
		"rule_id": ruleID,
	})
}

// FalseNegative handles POST /api/v1/logs/{id}/false-negative.
func (h *FeedbackHandler) FalseNegative(w http.ResponseWriter, r *http.Request) {
	if h.pool == nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", "database not available")
		return
	}

	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		RespondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
		return
	}

	logID, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_ID", "invalid log ID")
		return
	}

	var req struct {
		Reason string `json:"reason"`
		// Pattern override: if non-empty, use this as the rule pattern instead
		// of the raw request payload. Useful for fuzzed/encoded attacks.
		Pattern string `json:"pattern"`
	}
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			RespondError(w, http.StatusBadRequest, "INVALID_BODY", "invalid JSON body")
			return
		}
	}
	// F40: cap the reason to avoid unbounded Postgres writes.
	if len(req.Reason) > maxReasonLen {
		req.Reason = req.Reason[:maxReasonLen]
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	var logPath, logPayload string
	err = h.pool.QueryRow(ctx,
		`SELECT path, COALESCE(query, '') || ' ' || COALESCE(body, '') FROM request_logs WHERE id = $1`,
		logID,
	).Scan(&logPath, &logPayload)
	if err != nil {
		RespondError(w, http.StatusNotFound, "NOT_FOUND", "log entry not found")
		return
	}

	// Record FN via policy tuner (existing behavior).
	if h.policyTuner != nil {
		h.policyTuner.RecordFN(logPath)
	}

	// Auto-generate a rule from the offending payload.
	pattern := req.Pattern
	if pattern == "" {
		// Truncate payload to avoid unbounded rule patterns.
		pattern = strings.TrimSpace(logPayload)
		if len(pattern) > 200 {
			pattern = pattern[:200]
		}
	}
	if pattern == "" {
		pattern = logPath
	}

	// C-1: reject regex metacharacters in the user-supplied pattern. The
	// auto-generated rule must always be a literal string match. Allowing
	// user-supplied regex would let a malicious editor inject a ReDoS
	// pattern that locks the engine on subsequent requests.
	if hasRegexMeta(pattern) {
		RespondError(w, http.StatusBadRequest, "INVALID_PATTERN",
			"pattern contains regex metacharacters; auto-feedback rules are string matches only")
		return
	}
	// Defense-in-depth: still run HasReDoSRisk and regexp.Compile on the
	// (literal) pattern so a future change allowing regex metachars does
	// not silently expose the engine.
	if _, err := regexp.Compile(pattern); err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_PATTERN", "pattern does not compile")
		return
	}
	if err := rules.HasReDoSRisk(pattern); err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_PATTERN", err.Error())
		return
	}

	ruleName := fmt.Sprintf("auto-fn-%d-%s", time.Now().Unix(), claims.Username)
	var ruleID int
	// C-1: force match_type=string regardless of caller input. The pattern
	// is also literal-checked above so it cannot escalate to a regex rule.
	err = h.pool.QueryRow(ctx,
		`INSERT INTO rules (name, pattern, match_type, action, severity, paranoia_level, source, description, enabled)
		 VALUES ($1, $2, 'string', 'block', 'medium', 1, 'auto-feedback', $3, true)
		 RETURNING id`,
		ruleName, pattern, fmt.Sprintf("auto-generated from FN report: %s", req.Reason),
	).Scan(&ruleID)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "insert rule"))
		return
	}

	// Persist FN report row.
	var fnID int
	err = h.pool.QueryRow(ctx,
		`INSERT INTO false_negatives (log_id, path, payload, reason, reviewed_by, username, auto_rule_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
		logID, logPath, logPayload, req.Reason, claims.UserID, claims.Username, ruleID,
	).Scan(&fnID)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "insert false negative"))
		return
	}

	// Reload rule engine to pick up new rule.
	if h.ruleEngine != nil {
		h.ruleEngine.Reload()
	}

	RespondJSON(w, http.StatusCreated, map[string]interface{}{
		"id":       fnID,
		"log_id":   logID,
		"rule_id":  ruleID,
		"status":   "rule_created",
	})
}

// List handles GET /api/v1/false-positives
func (h *FeedbackHandler) List(w http.ResponseWriter, r *http.Request) {
	if h.pool == nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", "database not available")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage < 1 || perPage > 100 {
		perPage = 50
	}
	offset := (page - 1) * perPage

	rows, err := h.pool.Query(ctx,
		// L-20: use a window function so the total count comes back in
		// the same query as the page rows. Saves a round trip and avoids
		// stale counts between the two queries.
		`SELECT id, COALESCE(log_id, 0), COALESCE(rule_id, 0), COALESCE(reason, ''),
			COALESCE(reviewed_by, 0), created_at::text,
			COUNT(*) OVER() AS total
		 FROM false_positives
		 ORDER BY created_at DESC
		 LIMIT $1 OFFSET $2`, perPage, offset)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "database"))
		return
	}
	defer rows.Close()

	var fps []falsePositive
	var total int
	for rows.Next() {
		var fp falsePositive
		if err := rows.Scan(&fp.ID, &fp.LogID, &fp.RuleID, &fp.Reason,
			&fp.ReviewedBy, &fp.CreatedAt, &total); err != nil {
			RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "database"))
			return
		}
		fps = append(fps, fp)
	}
	if fps == nil {
		fps = []falsePositive{}
	}

	RespondJSONWithMeta(w, http.StatusOK, fps, &Meta{
		Page:    page,
		PerPage: perPage,
		Total:   total,
	})
}

// Delete handles DELETE /api/v1/false-positives/{id}
func (h *FeedbackHandler) Delete(w http.ResponseWriter, r *http.Request) {
	if h.pool == nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", "database not available")
		return
	}

	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_ID", "invalid false-positive ID")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	tag, err := h.pool.Exec(ctx, `DELETE FROM false_positives WHERE id = $1`, id)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "database"))
		return
	}
	if tag.RowsAffected() == 0 {
		RespondError(w, http.StatusNotFound, "NOT_FOUND", "false-positive not found")
		return
	}

	RespondJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// regexMetachars enumerates the characters that give a string regex
// semantics. Their presence in an auto-feedback pattern is rejected.
const regexMetachars = `.*+?^$()[]{}|\`
