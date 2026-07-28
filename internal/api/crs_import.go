package api

import (
	"encoding/json"
	"net/http"

	"github.com/user/waf/internal/rules"
)

// crsImportRequest is the payload for POST /rules/crs/import and
// POST /rules/crs/dry-run.
type crsImportRequest struct {
	Text string `json:"text"`
}

// crsImportResponse is the JSON returned by both endpoints.
type crsImportResponse struct {
	Imported int      `json:"imported"`
	Skipped  int      `json:"skipped"`
	Warnings []string `json:"warnings"`
	Rules    []rules.TemplateRule `json:"rules"`
}

// ImportCRS handles POST /api/v1/rules/crs/import — converts a CRS config
// blob into Aegis rule rows. Admin only.
func (h *RuleHandler) ImportCRS(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB cap on CRS blob
	var req crsImportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Text == "" {
		RespondError(w, http.StatusBadRequest, "INVALID_REQUEST", "text field required")
		return
	}
	result := rules.ImportCRS(req.Text)
	// Persist imported rules
	ctx := r.Context()
	persisted := 0
	for _, tr := range result.Rules {
		if _, err := h.pool.Exec(ctx,
			`INSERT INTO rules (name, pattern, match_type, action, severity, priority, paranoia_level, description, enabled, source)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, true, 'crs-import')
			 ON CONFLICT (name) DO NOTHING`,
			tr.Name, tr.Pattern, tr.MatchType, tr.Action, tr.Severity,
			tr.Priority, tr.ParanoiaLevel, tr.Description); err == nil {
			persisted++
		}
	}
	RespondJSON(w, http.StatusOK, crsImportResponse{
		Imported: persisted,
		Skipped:  result.Skipped,
		Warnings: result.Warnings,
		Rules:    result.Rules,
	})
}

// DryRunCRS handles POST /api/v1/rules/crs/dry-run — parses a CRS blob
// and returns what would be imported, without writing to the DB.
func (h *RuleHandler) DryRunCRS(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req crsImportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Text == "" {
		RespondError(w, http.StatusBadRequest, "INVALID_REQUEST", "text field required")
		return
	}
	result := rules.ImportCRS(req.Text)
	RespondJSON(w, http.StatusOK, crsImportResponse{
		Imported: len(result.Rules),
		Skipped:  result.Skipped,
		Warnings: result.Warnings,
		Rules:    result.Rules,
	})
}