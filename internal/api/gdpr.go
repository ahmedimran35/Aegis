package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/user/waf/internal/auth"
	"github.com/user/waf/internal/gdpr"
)

// GDPRHandler exposes GDPR data-subject rights endpoints.
type GDPRHandler struct {
	svc *gdpr.Service
}

func NewGDPRHandler(pool *pgxpool.Pool) *GDPRHandler {
	return &GDPRHandler{svc: gdpr.NewService(pool)}
}

// Export handles GET /api/v1/gdpr/export. Returns all data for current user.
func (h *GDPRHandler) Export(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil || claims.UserID == 0 {
		RespondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
		return
	}
	h.svc.HandleExport(w, r, claims.UserID)
}

// Delete handles POST /api/v1/gdpr/delete. Deletes all data for current user.
func (h *GDPRHandler) Delete(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil || claims.UserID == 0 {
		RespondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
		return
	}
	h.svc.HandleDelete(w, r, claims.UserID)
}

// Mount wires the GDPR routes onto r.
func (h *GDPRHandler) Mount(r chi.Router) {
	r.Route("/gdpr", func(r chi.Router) {
		r.Get("/export", h.Export)
		r.Post("/delete", h.Delete)
	})
}
