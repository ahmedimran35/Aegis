package api

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RuleSuggestionHandler handles AI rule suggestion endpoints.
type RuleSuggestionHandler struct {
	pool *pgxpool.Pool
}

// NewRuleSuggestionHandler creates a rule suggestion handler.
func NewRuleSuggestionHandler(pool *pgxpool.Pool) *RuleSuggestionHandler {
	return &RuleSuggestionHandler{pool: pool}
}

type ruleSuggestionRow struct {
	ID              int              `json:"id"`
	Pattern         string           `json:"pattern"`
	MatchType       string           `json:"match_type"`
	SuggestedAction string           `json:"suggested_action"`
	Confidence      float64          `json:"confidence"`
	SampleAttacks   json.RawMessage  `json:"sample_attacks"`
	Status          string           `json:"status"`
	CreatedAt       string           `json:"created_at"`
}

// List handles GET /api/v1/rules/suggestions
func (h *RuleSuggestionHandler) List(w http.ResponseWriter, r *http.Request) {
	rows, err := h.pool.Query(r.Context(),
		`SELECT id, pattern, match_type, suggested_action, confidence, sample_attacks, status, created_at::text
		 FROM ai_rule_suggestions ORDER BY created_at DESC LIMIT 100`)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "list suggestions"))
		return
	}
	defer rows.Close()

	var suggestions []ruleSuggestionRow
	for rows.Next() {
		var s ruleSuggestionRow
		if err := rows.Scan(&s.ID, &s.Pattern, &s.MatchType, &s.SuggestedAction, &s.Confidence, &s.SampleAttacks, &s.Status, &s.CreatedAt); err != nil {
			continue
		}
		suggestions = append(suggestions, s)
	}
	if suggestions == nil {
		suggestions = []ruleSuggestionRow{}
	}
	RespondJSON(w, http.StatusOK, suggestions)
}

// HandleAction handles POST /api/v1/rules/suggestions/{id}/{action}
func (h *RuleSuggestionHandler) HandleAction(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_ID", "invalid suggestion ID")
		return
	}

	action := chi.URLParam(r, "action")
	if action != "accept" && action != "reject" {
		RespondError(w, http.StatusBadRequest, "INVALID_ACTION", "action must be accept or reject")
		return
	}

	ctx := r.Context()

	if action == "accept" {
		// Get the suggestion
		var pattern, matchType, suggestedAction string
		err := h.pool.QueryRow(ctx,
			`SELECT pattern, match_type, suggested_action FROM ai_rule_suggestions WHERE id = $1 AND status = 'pending'`, id,
		).Scan(&pattern, &matchType, &suggestedAction)
		if err != nil {
			RespondError(w, http.StatusNotFound, "NOT_FOUND", "suggestion not found or already processed")
			return
		}

		// Create the rule from the suggestion
		_, err = h.pool.Exec(ctx,
			`INSERT INTO rules (name, pattern, match_type, action, severity, source, description)
			 VALUES ($1, $2, $3, $4, 'medium', 'ai_suggested', $5)`,
			"AI Suggested Rule #"+strconv.Itoa(id), pattern, matchType, suggestedAction,
			"Auto-generated from AI suggestion #"+strconv.Itoa(id))
		if err != nil {
			RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "create rule from suggestion"))
			return
		}

		// Update suggestion status
		if _, err := h.pool.Exec(ctx, `UPDATE ai_rule_suggestions SET status = 'accepted' WHERE id = $1`, id); err != nil {
			// Rule was created but status update failed — log but don't fail the request
			log.Printf("warning: failed to update suggestion %d status: %v", id, err)
		}
		RespondJSON(w, http.StatusOK, map[string]string{"status": "accepted"})
	} else {
		// Reject the suggestion
		tag, err := h.pool.Exec(ctx,
			`UPDATE ai_rule_suggestions SET status = 'rejected' WHERE id = $1 AND status = 'pending'`, id)
		if err != nil {
			RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "reject suggestion"))
			return
		}
		if tag.RowsAffected() == 0 {
			RespondError(w, http.StatusNotFound, "NOT_FOUND", "suggestion not found or already processed")
			return
		}
		RespondJSON(w, http.StatusOK, map[string]string{"status": "rejected"})
	}
}
