// Package api: rule export/import (P4-F6 + P4-F7).
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/user/waf/internal/auth"
	"github.com/user/waf/internal/rules"
	"gopkg.in/yaml.v3"
)

// ruleExport is the YAML shape produced/consumed by /rules/export and /rules/import.
type ruleExport struct {
	Rules    []ruleRow        `yaml:"rules" json:"rules"`
	Versions []ruleVersionRow `yaml:"versions" json:"versions"`
}

type ruleVersionRow struct {
	RuleID         int    `yaml:"rule_id" json:"rule_id"`
	Version        int    `yaml:"version" json:"version"`
	Action         string `yaml:"action" json:"action"`
	CreatedBy      int    `yaml:"created_by,omitempty" json:"created_by,omitempty"`
	CreatedByName  string `yaml:"created_by_name,omitempty" json:"created_by_name,omitempty"`
	ChangeNote     string `yaml:"change_note,omitempty" json:"change_note,omitempty"`
	CreatedAt      string `yaml:"created_at" json:"created_at"`
}

// ExportRules handles GET /api/v1/rules/export (P4-F6).
func (h *RuleHandler) ExportRules(w http.ResponseWriter, r *http.Request) {
	includeVersions := r.URL.Query().Get("include_versions") == "true"

	var bundle ruleExport
	rows, err := h.pool.Query(r.Context(),
		`SELECT id, name, pattern, match_type, action, severity, priority, enabled, hit_count, source,
		 COALESCE(description, ''), created_at::text, updated_at::text
		 FROM rules ORDER BY id`)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", "export query failed")
		return
	}
	defer rows.Close()
	for rows.Next() {
		var rr ruleRow
		if err := rows.Scan(&rr.ID, &rr.Name, &rr.Pattern, &rr.MatchType, &rr.Action,
			&rr.Severity, &rr.Priority, &rr.Enabled, &rr.HitCount, &rr.Source,
			&rr.Description, &rr.CreatedAt, &rr.UpdatedAt); err != nil {
			continue
		}
		bundle.Rules = append(bundle.Rules, rr)
	}

	if includeVersions {
		vrows, err := h.pool.Query(r.Context(),
			`SELECT rule_id, version, action, COALESCE(created_by, 0),
			 COALESCE(created_by_name, ''), COALESCE(change_note, ''), created_at::text
			 FROM rule_versions ORDER BY rule_id, version`)
		if err == nil {
			defer vrows.Close()
			for vrows.Next() {
				var v ruleVersionRow
				if err := vrows.Scan(&v.RuleID, &v.Version, &v.Action, &v.CreatedBy,
					&v.CreatedByName, &v.ChangeNote, &v.CreatedAt); err != nil {
					continue
				}
				bundle.Versions = append(bundle.Versions, v)
			}
		}
	}

	w.Header().Set("Content-Type", "application/x-yaml")
	w.Header().Set("Content-Disposition", `attachment; filename="aegis-rules.yaml"`)
	out, err := yaml.Marshal(&bundle)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "YAML_ERROR", err.Error())
		return
	}
	w.Write(out)
}

// ImportRules handles POST /api/v1/rules/import (P4-F7).
// Body: YAML bundle (or JSON). If query "force=true", overwrite existing rules
// with matching IDs. Otherwise refuse on conflict.
func (h *RuleHandler) ImportRules(w http.ResponseWriter, r *http.Request) {
	force := r.URL.Query().Get("force") == "true"

	// CRIT: cap body BEFORE reading to prevent OOM. Without this, an
	// attacker can post a multi-GB body and exhaust memory before the
	// size check fires.
	r.Body = http.MaxBytesReader(w, r.Body, 10*1024*1024)

	// Read body once; try YAML then JSON.
	body := make([]byte, 0, 64*1024)
	buf := make([]byte, 4096)
	for {
		n, err := r.Body.Read(buf)
		if n > 0 {
			body = append(body, buf[:n]...)
		}
		if err != nil {
			break
		}
		if len(body) > 10*1024*1024 {
			RespondError(w, http.StatusBadRequest, "TOO_LARGE", "import body > 10MB")
			return
		}
	}

	var bundle ruleExport
	if err := yaml.Unmarshal(body, &bundle); err != nil {
		if jerr := json.Unmarshal(body, &bundle); jerr != nil {
			RespondError(w, http.StatusBadRequest, "INVALID_FORMAT",
				"body must be YAML or JSON: yaml="+err.Error()+" json="+jerr.Error())
			return
		}
	}

	ctx := r.Context()
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", "tx failed")
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// C-3: pre-validate every regex pattern through the ReDoS structural
	// + probe gate. A pattern that fails the gate is never written, even
	// under force=true. This blocks importing `(a+)+$` style vectors.
	for i, rr := range bundle.Rules {
		if rr.MatchType == "regex" {
			if err := rules.HasReDoSRisk(rr.Pattern); err != nil {
				RespondError(w, http.StatusBadRequest, "REDOS_PATTERN",
					fmt.Sprintf("rule id=%d rejected: %v", rr.ID, err))
				_ = i
				return
			}
			if _, err := regexp.Compile(rr.Pattern); err != nil {
				RespondError(w, http.StatusBadRequest, "INVALID_REGEX",
					fmt.Sprintf("rule id=%d pattern does not compile: %v", rr.ID, err))
				return
			}
		}
	}

	var stats struct {
		RulesCreated    int      `json:"rules_created"`
		RulesUpdated    int      `json:"rules_updated"`
		RulesSkipped    int      `json:"rules_skipped"`
		VersionsImported int     `json:"versions_imported"`
		Errors          []string `json:"errors"`
	}

	for _, rr := range bundle.Rules {
		var exists bool
		_ = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM rules WHERE id=$1)`, rr.ID).Scan(&exists)
		if exists && !force {
			stats.RulesSkipped++
			stats.Errors = append(stats.Errors, fmt.Sprintf("rule id=%d exists (use force=true to overwrite)", rr.ID))
			continue
		}
		if exists {
			_, err := tx.Exec(ctx,
				`UPDATE rules SET name=$1, pattern=$2, match_type=$3, action=$4, severity=$5,
				 priority=$6, description=$7, updated_at=NOW() WHERE id=$8`,
				rr.Name, rr.Pattern, rr.MatchType, rr.Action, rr.Severity, rr.Priority,
				rr.Description, rr.ID)
			if err != nil {
				stats.Errors = append(stats.Errors, fmt.Sprintf("update id=%d: %v", rr.ID, err))
				continue
			}
			stats.RulesUpdated++
		} else {
			// On import we use the original ID (assumes operator controls IDs).
			_, err := tx.Exec(ctx,
				`INSERT INTO rules (id, name, pattern, match_type, action, severity, priority, description)
				 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
				 ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, pattern=EXCLUDED.pattern,
				   match_type=EXCLUDED.match_type, action=EXCLUDED.action, severity=EXCLUDED.severity,
				   priority=EXCLUDED.priority, description=EXCLUDED.description, updated_at=NOW()`,
				rr.ID, rr.Name, rr.Pattern, rr.MatchType, rr.Action, rr.Severity, rr.Priority, rr.Description)
			if err != nil {
				stats.Errors = append(stats.Errors, fmt.Sprintf("insert id=%d: %v", rr.ID, err))
				continue
			}
			stats.RulesCreated++
		}
	}

	for _, v := range bundle.Versions {
		_, err := tx.Exec(ctx,
			`INSERT INTO rule_versions (rule_id, version, snapshot, action, created_by, created_by_name, change_note)
			 VALUES ($1, $2, $3, $4, $5, $6, $7)
			 ON CONFLICT (rule_id, version) DO NOTHING`,
			v.RuleID, v.Version, []byte("{}"), v.Action, nullInt(v.CreatedBy), v.CreatedByName, v.ChangeNote)
		if err != nil {
			stats.Errors = append(stats.Errors, fmt.Sprintf("version rule=%d v=%d: %v", v.RuleID, v.Version, err))
			continue
		}
		stats.VersionsImported++
	}

	if err := tx.Commit(ctx); err != nil {
		RespondError(w, http.StatusInternalServerError, "COMMIT_FAILED", err.Error())
		return
	}
	RespondJSON(w, http.StatusOK, stats)
}

func nullInt(i int) interface{} {
	if i == 0 {
		return nil
	}
	return i
}

// ApproveRule handles POST /api/v1/rules/{id}/approve (P4-F8).
func (h *RuleHandler) ApproveRule(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_ID", "invalid rule ID")
		return
	}
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		RespondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "auth required")
		return
	}
	tag, err := h.pool.Exec(r.Context(),
		`UPDATE rules SET approved_by=$1, approved_at=NOW(), pending_approval=FALSE WHERE id=$2`,
		claims.UserID, id)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", "approve failed")
		return
	}
	if tag.RowsAffected() == 0 {
		RespondError(w, http.StatusNotFound, "NOT_FOUND", "rule not found")
		return
	}
	if h.audit != nil {
		h.audit.LogRuleChange(claims.UserID, claims.Username, "approve", id, nil, clientIP(r))
	}
	RespondJSON(w, http.StatusOK, map[string]any{"id": id, "approved": true})
}

// ToggleDryRun handles POST /api/v1/rules/{id}/dry-run/toggle (P4-F9).
func (h *RuleHandler) ToggleDryRun(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_ID", "invalid rule ID")
		return
	}
	var rule ruleRow
	if err := h.pool.QueryRow(r.Context(),
		`UPDATE rules SET dry_run = NOT dry_run, updated_at = NOW() WHERE id = $1
		 RETURNING id, name, pattern, match_type, action, severity, priority, enabled, hit_count, source,
		           COALESCE(description, ''), created_at::text, updated_at::text`, id,
	).Scan(&rule.ID, &rule.Name, &rule.Pattern, &rule.MatchType, &rule.Action,
		&rule.Severity, &rule.Priority, &rule.Enabled, &rule.HitCount, &rule.Source,
		&rule.Description, &rule.CreatedAt, &rule.UpdatedAt); err != nil {
		RespondError(w, http.StatusNotFound, "NOT_FOUND", "rule not found")
		return
	}
	claims := auth.ClaimsFromContext(r.Context())
	if claims != nil && h.audit != nil {
		h.audit.LogRuleChange(claims.UserID, claims.Username, "dry_run_toggle", id,
			map[string]bool{"dry_run": !rule.Enabled}, clientIP(r))
	}
	_ = rule // included in returned data via next line
	RespondJSON(w, http.StatusOK, map[string]any{"id": id})
}
