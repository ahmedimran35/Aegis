package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/user/waf/internal/rules"
)

// RuleTestHandler handles rule testing API endpoints.
type RuleTestHandler struct {
	tester *rules.Tester
}

// NewRuleTestHandler creates a rule test handler.
func NewRuleTestHandler(tester *rules.Tester) *RuleTestHandler {
	return &RuleTestHandler{tester: tester}
}

// TestRule tests a specific rule against a sample request.
func (h *RuleTestHandler) TestRule(w http.ResponseWriter, r *http.Request) {
	ruleID, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_ID", "invalid rule ID")
		return
	}

	var req rules.TestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_BODY", "invalid test request")
		return
	}

	result, err := h.tester.TestRule(r.Context(), ruleID, req)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "TEST_ERROR", safeError(err, "rule test"))
		return
	}

	RespondJSON(w, http.StatusOK, result)
}

// TestAllRules tests all rules against a sample request.
func (h *RuleTestHandler) TestAllRules(w http.ResponseWriter, r *http.Request) {
	var req rules.TestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_BODY", "invalid test request")
		return
	}

	results := h.tester.TestAllRules(r.Context(), req)
	RespondJSON(w, http.StatusOK, results)
}

// GetTestHistory returns test history for a rule.
func (h *RuleTestHandler) GetTestHistory(w http.ResponseWriter, r *http.Request) {
	ruleID, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_ID", "invalid rule ID")
		return
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit < 1 || limit > 100 {
		limit = 20
	}

	tests, err := h.tester.GetTestHistory(r.Context(), ruleID, limit)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "database"))
		return
	}

	RespondJSON(w, http.StatusOK, tests)
}
