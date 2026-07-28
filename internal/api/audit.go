package api

import (
	"net/http"
	"strconv"

	"github.com/user/waf/internal/audit"
)

// AuditHandler handles audit log API endpoints.
type AuditHandler struct {
	logger *audit.Logger
}

// NewAuditHandler creates an audit handler.
func NewAuditHandler(logger *audit.Logger) *AuditHandler {
	return &AuditHandler{logger: logger}
}

// List returns audit log entries.
func (h *AuditHandler) List(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage < 1 || perPage > 100 {
		perPage = 50
	}
	resourceType := r.URL.Query().Get("resource_type")

	entries, total, err := h.logger.GetEntries(r.Context(), page, perPage, resourceType)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "database"))
		return
	}

	RespondJSONWithMeta(w, http.StatusOK, entries, &Meta{
		Page:    page,
		PerPage: perPage,
		Total:   total,
	})
}
