package api

import (
	"net/http"

	"github.com/user/waf/internal/middleware"
)

// BodyInspectHandler handles body inspection API endpoints.
type BodyInspectHandler struct {
	inspector *middleware.BodyInspector
}

// NewBodyInspectHandler creates a body inspection handler.
func NewBodyInspectHandler(inspector *middleware.BodyInspector) *BodyInspectHandler {
	return &BodyInspectHandler{inspector: inspector}
}

// Stats returns body inspection statistics.
func (h *BodyInspectHandler) Stats(w http.ResponseWriter, r *http.Request) {
	stats := h.inspector.Stats()
	RespondJSON(w, http.StatusOK, stats)
}
