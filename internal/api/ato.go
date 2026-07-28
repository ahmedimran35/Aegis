package api

import (
	"net"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/user/waf/internal/middleware"
)

// ATOHandler handles ATO-related API endpoints.
type ATOHandler struct {
	detector *middleware.ATODetector
}

// NewATOHandler creates a new ATO handler.
func NewATOHandler(detector *middleware.ATODetector) *ATOHandler {
	return &ATOHandler{detector: detector}
}

// Stats handles GET /api/v1/ato/stats
func (h *ATOHandler) Stats(w http.ResponseWriter, r *http.Request) {
	stats := h.detector.GetStats(r.Context())
	RespondJSON(w, http.StatusOK, stats)
}

// Events handles GET /api/v1/ato/events
func (h *ATOHandler) Events(w http.ResponseWriter, r *http.Request) {
	events, err := h.detector.GetRecentEvents(r.Context(), 50)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", "failed to fetch ATO events")
		return
	}
	if events == nil {
		events = []map[string]interface{}{}
	}
	RespondJSON(w, http.StatusOK, events)
}

// Unlock handles POST /api/v1/ato/unlock/{ip}
func (h *ATOHandler) Unlock(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	if ip == "" {
		RespondError(w, http.StatusBadRequest, "INVALID_IP", "IP address is required")
		return
	}
	if net.ParseIP(ip) == nil {
		RespondError(w, http.StatusBadRequest, "INVALID_IP", "invalid IP address format")
		return
	}
	h.detector.UnlockIP(r.Context(), ip)
	RespondJSON(w, http.StatusOK, map[string]string{"ip": ip, "status": "unlocked"})
}
