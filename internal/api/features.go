package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/user/waf/internal/audit"
	wafmw "github.com/user/waf/internal/middleware"
)

// ============================================================================
// Admin/read handlers for the new "features" endpoints.
// ============================================================================

// ---- JWT allowlist ----
type JWTAllowlist struct {
	pool  *pgxpool.Pool
	guard *wafmw.JWTGuard
	audit *audit.Logger
}

func NewJWTAllowlist(pool *pgxpool.Pool, guard *wafmw.JWTGuard, al *audit.Logger) *JWTAllowlist {
	return &JWTAllowlist{pool: pool, guard: guard, audit: al}
}

type jwtAlg struct {
	ID        int    `json:"id"`
	Alg       string `json:"alg"`
	Issuer    string `json:"issuer"`
	Enabled   bool   `json:"enabled"`
	CreatedAt string `json:"created_at"`
}

func (h *JWTAllowlist) List(w http.ResponseWriter, r *http.Request) {
	rows, err := h.pool.Query(r.Context(),
		`SELECT id, alg, issuer, enabled, created_at::text FROM jwt_allowlist ORDER BY alg`)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
		return
	}
	defer rows.Close()
	out := []jwtAlg{}
	for rows.Next() {
		var a jwtAlg
		if err := rows.Scan(&a.ID, &a.Alg, &a.Issuer, &a.Enabled, &a.CreatedAt); err == nil {
			out = append(out, a)
		}
	}
	RespondJSON(w, http.StatusOK, out)
}

type jwtAddReq struct {
	Alg     string `json:"alg"`
	Issuer  string `json:"issuer"`
	Enabled *bool  `json:"enabled"`
}

func (h *JWTAllowlist) Add(w http.ResponseWriter, r *http.Request) {
	var req jwtAddReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_JSON", err.Error())
		return
	}
	if req.Alg == "" {
		RespondError(w, http.StatusBadRequest, "MISSING_FIELDS", "alg is required")
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	issuer := req.Issuer
	if issuer == "" {
		issuer = "*"
	}
	var a jwtAlg
	err := h.pool.QueryRow(r.Context(),
		`INSERT INTO jwt_allowlist (alg, issuer, enabled) VALUES ($1, $2, $3)
		 ON CONFLICT (alg, issuer) DO UPDATE SET enabled = EXCLUDED.enabled
		 RETURNING id, alg, issuer, enabled, created_at::text`,
		req.Alg, issuer, enabled,
	).Scan(&a.ID, &a.Alg, &a.Issuer, &a.Enabled, &a.CreatedAt)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
		return
	}
	if h.guard != nil {
		_ = h.guard.Refresh(r.Context())
	}
	RespondJSON(w, http.StatusCreated, a)
}

func (h *JWTAllowlist) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_ID", "invalid id")
		return
	}
	if _, err := h.pool.Exec(r.Context(), `DELETE FROM jwt_allowlist WHERE id = $1`, id); err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
		return
	}
	if h.guard != nil {
		_ = h.guard.Refresh(r.Context())
	}
	RespondJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

// ---- CVE Feed ----
type CVEManager struct {
	pool  *pgxpool.Pool
	audit *audit.Logger
}

func NewCVEManager(pool *pgxpool.Pool, al *audit.Logger) *CVEManager { return &CVEManager{pool: pool, audit: al} }

type cveRow struct {
	ID              int     `json:"id"`
	CVEID           string  `json:"cve_id"`
	CVSSScore       float64 `json:"cvss_score"`
	Severity        string  `json:"severity"`
	AffectedProduct string  `json:"affected_product"`
	RulePattern     string  `json:"rule_pattern"`
	RuleAction      string  `json:"rule_action"`
	RuleMatch       string  `json:"rule_match"`
	Description     string  `json:"description"`
	PublishedAt     string  `json:"published_at"`
	AutoApply        bool    `json:"auto_apply"`
	AppliedAt       string  `json:"applied_at"`
	VirtualPatchID  *int    `json:"virtual_patch_id"`
	CreatedAt       string  `json:"created_at"`
}

func (h *CVEManager) List(w http.ResponseWriter, r *http.Request) {
	rows, err := h.pool.Query(r.Context(),
		`SELECT id, cve_id, COALESCE(cvss_score,0), COALESCE(severity,'medium'),
		        COALESCE(affected_product,''), rule_pattern, rule_action, rule_match,
		        COALESCE(description,''), COALESCE(published_at::text,''), auto_apply,
		        COALESCE(applied_at::text,''), virtual_patch_id, created_at::text
		 FROM cve_feed ORDER BY published_at DESC NULLS LAST, id DESC LIMIT 200`)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
		return
	}
	defer rows.Close()
	out := []cveRow{}
	for rows.Next() {
		var r cveRow
		if err := rows.Scan(&r.ID, &r.CVEID, &r.CVSSScore, &r.Severity, &r.AffectedProduct, &r.RulePattern, &r.RuleAction, &r.RuleMatch, &r.Description, &r.PublishedAt, &r.AutoApply, &r.AppliedAt, &r.VirtualPatchID, &r.CreatedAt); err == nil {
			out = append(out, r)
		}
	}
	RespondJSON(w, http.StatusOK, out)
}

// ---- LLM Protection rules ----
type LLMManager struct {
	pool *pgxpool.Pool
}

func NewLLMManager(pool *pgxpool.Pool) *LLMManager { return &LLMManager{pool: pool} }

func (h *LLMManager) List(w http.ResponseWriter, r *http.Request) {
	rows, _ := h.pool.Query(r.Context(),
		`SELECT id, name, pattern, kind, action, enabled, hits, created_at::text FROM llm_protection_rules ORDER BY id DESC LIMIT 200`)
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, hits int
		var name, pattern, kind, action, created string
		var enabled bool
		if err := rows.Scan(&id, &name, &pattern, &kind, &action, &enabled, &hits, &created); err == nil {
			out = append(out, map[string]any{
				"id": id, "name": name, "pattern": pattern, "kind": kind,
				"action": action, "enabled": enabled, "hits": hits, "created_at": created,
			})
		}
	}
	RespondJSON(w, http.StatusOK, out)
}

// ---- Anomaly events ----
type AnomalyReader struct{ pool *pgxpool.Pool }

func (h *AnomalyReader) ListEvents(w http.ResponseWriter, r *http.Request) {
	rows, _ := h.pool.Query(r.Context(),
		`SELECT id, path, method, observed_qps, baseline_qps, multiplier, severity, created_at::text
		 FROM endpoint_anomaly_events ORDER BY created_at DESC LIMIT 200`)
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int
		var path, method, sev, created string
		var obs, base, mult float64
		if err := rows.Scan(&id, &path, &method, &obs, &base, &mult, &sev, &created); err == nil {
			out = append(out, map[string]any{
				"id": id, "path": path, "method": method,
				"observed_qps": obs, "baseline_qps": base, "multiplier": mult,
				"severity": sev, "created_at": created,
			})
		}
	}
	RespondJSON(w, http.StatusOK, out)
}

func (h *AnomalyReader) ListBaselines(w http.ResponseWriter, r *http.Request) {
	rows, _ := h.pool.Query(r.Context(),
		`SELECT id, path, method, window_start::text, total, blocked, p95_latency_ms, bytes_total
		 FROM endpoint_anomaly ORDER BY window_start DESC LIMIT 200`)
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, total, blocked, p95, bytes int
		var path, method, win string
		if err := rows.Scan(&id, &path, &method, &win, &total, &blocked, &p95, &bytes); err == nil {
			out = append(out, map[string]any{
				"id": id, "path": path, "method": method, "window_start": win,
				"total": total, "blocked": blocked, "p95_latency_ms": p95, "bytes_total": bytes,
			})
		}
	}
	RespondJSON(w, http.StatusOK, out)
}

// ---- Browser challenge ----
type ChallengeHandler struct {
	pool *pgxpool.Pool
	ch   *wafmw.BrowserChallenge
}

func NewChallengeHandler(pool *pgxpool.Pool, ch *wafmw.BrowserChallenge) *ChallengeHandler {
	return &ChallengeHandler{pool: pool, ch: ch}
}
func (h *ChallengeHandler) Issue(w http.ResponseWriter, r *http.Request) { h.ch.Issue(w, r) }
func (h *ChallengeHandler) Solve(w http.ResponseWriter, r *http.Request) { h.ch.Solve(w, r) }

// ---- Upload scans ----
type UploadReader struct{ pool *pgxpool.Pool }

func (h *UploadReader) List(w http.ResponseWriter, r *http.Request) {
	rows, _ := h.pool.Query(r.Context(),
		`SELECT id, COALESCE(ip::text,''), COALESCE(content_type,''), COALESCE(filename,''),
		        size_bytes, COALESCE(detected_magic,''), verdict, COALESCE(matched_rule,''),
		        created_at::text
		 FROM upload_scans ORDER BY created_at DESC LIMIT 200`)
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, size int
		var ip, ct, fn, magic, verdict, rule, created string
		if err := rows.Scan(&id, &ip, &ct, &fn, &size, &magic, &verdict, &rule, &created); err == nil {
			out = append(out, map[string]any{
				"id": id, "ip": ip, "content_type": ct, "filename": fn,
				"size_bytes": size, "detected_magic": magic, "verdict": verdict,
				"matched_rule": rule, "created_at": created,
			})
		}
	}
	RespondJSON(w, http.StatusOK, out)
}

// ---- Credential stuffing ----
type StuffingReader struct{ pool *pgxpool.Pool }

func (h *StuffingReader) List(w http.ResponseWriter, r *http.Request) {
	rows, _ := h.pool.Query(r.Context(),
		`SELECT id, ip::text, username, distinct_users_count, attempt_count, status, blocked, created_at::text
		 FROM credential_stuffing_events ORDER BY created_at DESC LIMIT 200`)
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, distinct, attempts int
		var ip, username, status, created string
		var blocked bool
		if err := rows.Scan(&id, &ip, &username, &distinct, &attempts, &status, &blocked, &created); err == nil {
			out = append(out, map[string]any{
				"id": id, "ip": ip, "username": username,
				"distinct_users_count": distinct, "attempt_count": attempts,
				"status": status, "blocked": blocked, "created_at": created,
			})
		}
	}
	RespondJSON(w, http.StatusOK, out)
}

// ---- ASM findings ----
type ASMReader struct{ pool *pgxpool.Pool }

func (h *ASMReader) List(w http.ResponseWriter, r *http.Request) {
	rows, _ := h.pool.Query(r.Context(),
		`SELECT id, asset_kind, asset_value, severity, source, COALESCE(notes,''),
		        discovered_at::text, last_seen_at::text
		 FROM asm_findings ORDER BY last_seen_at DESC LIMIT 200`)
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int
		var kind, value, sev, source, notes, discovered, lastSeen string
		if err := rows.Scan(&id, &kind, &value, &sev, &source, &notes, &discovered, &lastSeen); err == nil {
			out = append(out, map[string]any{
				"id": id, "asset_kind": kind, "asset_value": value,
				"severity": sev, "source": source, "notes": notes,
				"discovered_at": discovered, "last_seen_at": lastSeen,
			})
		}
	}
	RespondJSON(w, http.StatusOK, out)
}

// ---- TestScan: admin-only endpoint to verify the upload scan pipeline ----
type testScanReq struct {
	IP           string `json:"ip"`
	ContentType  string `json:"content_type"`
	Filename     string `json:"filename"`
	Magic        string `json:"magic"`
	Verdict      string `json:"verdict"`
	MatchedRule  string `json:"matched_rule"`
	SizeBytes    int    `json:"size_bytes"`
}

func (h *UploadReader) TestScan(w http.ResponseWriter, r *http.Request) {
	if h.pool == nil {
		http.Error(w, "db unavailable", http.StatusServiceUnavailable)
		return
	}
	var req testScanReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_JSON", err.Error())
		return
	}
	if req.SizeBytes == 0 {
		req.SizeBytes = 1024
	}
	if req.ContentType == "" {
		req.ContentType = "application/octet-stream"
	}
	if req.Magic == "" {
		req.Magic = "PDF-1.4"
	}
	if req.Verdict == "" {
		req.Verdict = "allow"
	}
	wafmw.RecordUploadScan(h.pool, req.IP, req.ContentType, req.Filename, req.Magic, req.Verdict, req.MatchedRule, req.SizeBytes)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte(`{"accepted":true,"note":"scan record written by middleware RecordUploadScan"}`))
}
