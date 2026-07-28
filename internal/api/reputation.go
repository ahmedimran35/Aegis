package api

import (
	"net"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/user/waf/internal/reputation"
)

// ReputationHandler handles reputation API endpoints.
type ReputationHandler struct {
	client *reputation.Client
}

// NewReputationHandler creates a new reputation handler.
func NewReputationHandler(client *reputation.Client) *ReputationHandler {
	return &ReputationHandler{client: client}
}

// Stats handles GET /api/v1/reputation/stats
func (h *ReputationHandler) Stats(w http.ResponseWriter, r *http.Request) {
	stats := h.client.GetStats(r.Context())
	RespondJSON(w, http.StatusOK, stats)
}

// Check handles POST /api/v1/reputation/check/{ip}
func (h *ReputationHandler) Check(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	if ip == "" {
		RespondError(w, http.StatusBadRequest, "MISSING_IP", "IP address is required")
		return
	}
	if parsed := net.ParseIP(ip); parsed == nil {
		RespondError(w, http.StatusBadRequest, "INVALID_IP", "invalid IP address")
		return
	}

	result, err := h.client.CheckIP(r.Context(), ip)
	if err != nil {
		RespondError(w, http.StatusServiceUnavailable, "REPUTATION_ERROR", err.Error())
		return
	}

	RespondJSON(w, http.StatusOK, result)
}

// Top handles GET /api/v1/reputation/top
func (h *ReputationHandler) Top(w http.ResponseWriter, r *http.Request) {
	entries, err := h.client.GetTopLookups(r.Context())
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", "failed to retrieve top lookups")
		return
	}
	if entries == nil {
		entries = []reputation.TopEntry{}
	}
	RespondJSON(w, http.StatusOK, entries)
}
