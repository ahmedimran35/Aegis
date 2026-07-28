package api

import (
	"net/http"
	"strconv"

	"github.com/user/waf/internal/middleware"
)

// HoneypotHandler handles honeypot API endpoints.
type HoneypotHandler struct {
	trap *middleware.HoneypotTrap
}

// NewHoneypotHandler creates a honeypot handler.
func NewHoneypotHandler(trap *middleware.HoneypotTrap) *HoneypotHandler {
	return &HoneypotHandler{trap: trap}
}

// ListHits returns recent honeypot hits.
func (h *HoneypotHandler) ListHits(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage < 1 || perPage > 100 {
		perPage = 50
	}

	hits, total, err := h.trap.GetHits(r.Context(), page, perPage)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "database"))
		return
	}

	RespondJSONWithMeta(w, http.StatusOK, hits, &Meta{
		Page:    page,
		PerPage: perPage,
		Total:   total,
	})
}

// Stats returns honeypot statistics.
func (h *HoneypotHandler) Stats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.trap.GetStats(r.Context())
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "database"))
		return
	}

	RespondJSON(w, http.StatusOK, stats)
}
