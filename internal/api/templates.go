package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/user/waf/internal/rules"
)

type TemplateHandler struct {
	pool *pgxpool.Pool
}

func NewTemplateHandler(pool *pgxpool.Pool) *TemplateHandler {
	return &TemplateHandler{pool: pool}
}

// List returns all available protection templates.
func (h *TemplateHandler) List(w http.ResponseWriter, r *http.Request) {
	templates := rules.GetTemplates()
	var result []map[string]interface{}
	for _, t := range templates {
		result = append(result, map[string]interface{}{
			"id":             t.ID,
			"name":           t.Name,
			"description":    t.Description,
			"paranoia_level": t.ParanoiaLevel,
			"rule_count":     len(t.Rules),
		})
	}
	RespondJSON(w, http.StatusOK, result)
}

// Get returns a single template with all its rules.
func (h *TemplateHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	tmpl := rules.GetTemplate(id)
	if tmpl == nil {
		RespondError(w, http.StatusNotFound, "NOT_FOUND", "template not found")
		return
	}
	var ruleList []map[string]interface{}
	for _, rule := range tmpl.Rules {
		ruleList = append(ruleList, map[string]interface{}{
			"name":           rule.Name,
			"pattern":        rule.Pattern,
			"match_type":     rule.MatchType,
			"action":         rule.Action,
			"severity":       rule.Severity,
			"priority":       rule.Priority,
			"paranoia_level": rule.ParanoiaLevel,
			"description":    rule.Description,
		})
	}
	RespondJSON(w, http.StatusOK, map[string]interface{}{
		"id":             tmpl.ID,
		"name":           tmpl.Name,
		"description":    tmpl.Description,
		"paranoia_level": tmpl.ParanoiaLevel,
		"rules":          ruleList,
	})
}

// Apply applies a protection template, inserting its rules into the database.
func (h *TemplateHandler) Apply(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	count, err := rules.ApplyTemplate(r.Context(), h.pool, id)
	if err != nil {
		RespondError(w, http.StatusBadRequest, "APPLY_FAILED", err.Error())
		return
	}
	RespondJSON(w, http.StatusOK, map[string]interface{}{
		"success":    true,
		"message":    "template applied successfully",
		"rules_added": count,
	})
}
