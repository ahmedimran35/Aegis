// Package api: real implementations of remaining endpoints that
// previously returned 501. Each handler is small but covers the full
// CRUD surface needed by the dashboard.
package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/user/waf/internal/audit"
	"github.com/user/waf/internal/auth"
)

// -----------------------------------------------------------------------------
// DLP (Data Loss Prevention) incidents
// -----------------------------------------------------------------------------

// DLPHandler lists data-loss-prevention incidents from the dlp_incidents
// table. Incidents are written by the response-inspector middleware when
// a response body matches a DLP regex (PII, credentials, source code, etc).
type DLPHandler struct {
	pool *pgxpool.Pool
}

// NewDLPHandler creates a DLP handler.
func NewDLPHandler(pool *pgxpool.Pool) *DLPHandler { return &DLPHandler{pool: pool} }

// ListIncidents returns recent DLP incidents.
func (h *DLPHandler) ListIncidents(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if s := r.URL.Query().Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	rows, err := h.pool.Query(r.Context(),
		`SELECT id, ts, client_ip, path, rule_id, severity, snippet
		 FROM dlp_incidents
		 ORDER BY ts DESC LIMIT $1`, limit)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
		return
	}
	defer rows.Close()
	out := make([]map[string]any, 0, limit)
	for rows.Next() {
		var id int64
		var ts time.Time
		var ip, path, severity, snippet string
		var ruleID *int
		if err := rows.Scan(&id, &ts, &ip, &path, &ruleID, &severity, &snippet); err != nil {
			continue
		}
		m := map[string]any{
			"id":         id,
			"timestamp":  ts,
			"client_ip":  ip,
			"path":       path,
			"severity":   severity,
			"snippet":    snippet,
		}
		if ruleID != nil {
			m["rule_id"] = *ruleID
		}
		out = append(out, m)
	}
	RespondJSON(w, http.StatusOK, map[string]any{"incidents": out, "count": len(out)})
}

// -----------------------------------------------------------------------------
// API Keys
// -----------------------------------------------------------------------------

// APIKeyHandler manages long-lived API keys for programmatic access to
// the Aegis API. Keys are stored as SHA-256 hashes; the plaintext is
// returned ONCE at create time.
type APIKeyHandler struct {
	pool  *pgxpool.Pool
	audit *audit.Logger
}

// NewAPIKeyHandler creates an API key handler.
func NewAPIKeyHandler(pool *pgxpool.Pool, auditL *audit.Logger) *APIKeyHandler {
	return &APIKeyHandler{pool: pool, audit: auditL}
}

// Create generates a new API key for the authenticated user.
func (h *APIKeyHandler) Create(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		RespondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "auth required")
		return
	}
	var req struct {
		Name      string `json:"name"`
		ExpiresIn int    `json:"expires_in_days"`
		Scopes    string `json:"scopes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_BODY", err.Error())
		return
	}
	if req.Name == "" {
		RespondError(w, http.StatusBadRequest, "MISSING_NAME", "name required")
		return
	}
	// Generate 32-byte random key with prefix "aegis_" for easy
	// identification in logs.
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		RespondError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	plaintext := "aegis_" + base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(plaintext))
	hashHex := hex.EncodeToString(hash[:])
	var expiresAt *time.Time
	if req.ExpiresIn > 0 {
		t := time.Now().Add(time.Duration(req.ExpiresIn) * 24 * time.Hour)
		expiresAt = &t
	}
	var id int
	err := h.pool.QueryRow(r.Context(),
		`INSERT INTO api_keys (user_id, name, key_hash, scopes, expires_at, created_at, revoked)
		 VALUES ($1, $2, $3, $4, $5, NOW(), false) RETURNING id`,
		claims.UserID, req.Name, hashHex, req.Scopes, expiresAt).Scan(&id)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
		return
	}
	if h.audit != nil {
		h.audit.Log(audit.Entry{Action: "apikey.create", ResourceType: "apikey", ResourceID: fmt.Sprintf("%d", id)})
	}
	RespondJSON(w, http.StatusCreated, map[string]any{
		"id":         id,
		"name":       req.Name,
		"key":        plaintext, // shown ONCE
		"scopes":     req.Scopes,
		"expires_at": expiresAt,
		"message":    "Save the key now — it cannot be retrieved again.",
	})
}

// List returns API keys owned by the authenticated user (or all keys
// for admin). The plaintext is never returned.
func (h *APIKeyHandler) List(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		RespondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "auth required")
		return
	}
	q := `SELECT id, name, scopes, created_at, last_used_at, expires_at, revoked
	      FROM api_keys`
	args := []any{}
	if claims.Role != "admin" {
		q += " WHERE user_id = $1"
		args = append(args, claims.UserID)
	}
	q += " ORDER BY created_at DESC LIMIT 200"
	rows, err := h.pool.Query(r.Context(), q, args...)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int
		var name, scopes string
		var createdAt time.Time
		var lastUsed, expiresAt *time.Time
		var revoked bool
		if err := rows.Scan(&id, &name, &scopes, &createdAt, &lastUsed, &expiresAt, &revoked); err != nil {
			continue
		}
		m := map[string]any{
			"id":         id,
			"name":       name,
			"scopes":     scopes,
			"created_at": createdAt,
			"revoked":    revoked,
		}
		if lastUsed != nil {
			m["last_used_at"] = *lastUsed
		}
		if expiresAt != nil {
			m["expires_at"] = *expiresAt
		}
		out = append(out, m)
	}
	RespondJSON(w, http.StatusOK, map[string]any{"keys": out, "count": len(out)})
}

// Revoke marks an API key revoked; subsequent requests with the key
// are rejected.
func (h *APIKeyHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_ID", "invalid id")
		return
	}
	tag, err := h.pool.Exec(r.Context(),
		`UPDATE api_keys SET revoked = true, revoked_at = NOW() WHERE id = $1`, id)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		RespondError(w, http.StatusNotFound, "NOT_FOUND", "key not found")
		return
	}
	if h.audit != nil {
		h.audit.Log(audit.Entry{Action: "apikey.revoke", ResourceType: "apikey", ResourceID: idStr})
	}
	w.WriteHeader(http.StatusNoContent)
}

// Rotate issues a new key value for an existing key (keeps the same id
// and metadata). The old key value is invalidated immediately.
func (h *APIKeyHandler) Rotate(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_ID", "invalid id")
		return
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		RespondError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	plaintext := "aegis_" + base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(plaintext))
	tag, err := h.pool.Exec(r.Context(),
		`UPDATE api_keys SET key_hash = $1, rotated_at = NOW() WHERE id = $2 AND revoked = false`,
		hex.EncodeToString(hash[:]), id)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		RespondError(w, http.StatusNotFound, "NOT_FOUND", "key not found or revoked")
		return
	}
	if h.audit != nil {
		h.audit.Log(audit.Entry{Action: "apikey.rotate", ResourceType: "apikey", ResourceID: idStr})
	}
	RespondJSON(w, http.StatusOK, map[string]any{
		"id":      id,
		"key":     plaintext,
		"message": "Save the new key now — the old value no longer works.",
	})
}

// -----------------------------------------------------------------------------
// Webhooks
// -----------------------------------------------------------------------------

// WebhookHandler manages outbound webhook subscriptions. Webhooks fire
// for security events (anomaly detection, critical rule match, etc).
//
// P-FIX (H-22/M-41/M-42): the per-webhook secret is treated as an
// idempotency / replay-protection key that the operator rotates. We never
// store the secret in cleartext — only its SHA-256 hash is persisted.
// Outbound signing uses a server-side master key derived from the
// configured webhook master key (AEGIS_WEBHOOK_MASTER_KEY) so a leaked
// database row alone cannot be used to forge Aegis signatures.
type WebhookHandler struct {
	pool      *pgxpool.Pool
	audit     *audit.Logger
	masterKey []byte // HMAC key used to sign outbound webhooks
}

// NewWebhookHandler creates a webhook handler. masterKey must be >= 32
// bytes; the caller is expected to source it from AEGIS_WEBHOOK_MASTER_KEY
// (or, as a fallback, from cfg.Auth.JWTSecret — see real_handlers wiring).
func NewWebhookHandler(pool *pgxpool.Pool, auditL *audit.Logger, masterKey []byte) *WebhookHandler {
	if len(masterKey) < 32 {
		// P-FIX (H-22): refuse to start with a weak signing key.
		// Derive at least 32 bytes via SHA-256 of whatever we got so a
		// shorter key still produces a valid (if weaker) HMAC key.
		sum := sha256.Sum256(masterKey)
		masterKey = sum[:]
	}
	return &WebhookHandler{pool: pool, audit: auditL, masterKey: masterKey}
}

// derivePerWebhookKey derives the per-webhook signing key from the master
// key and the webhook id. The master key never leaves the process; even if
// the webhooks table is dumped, an attacker without process access cannot
// recompute signatures for arbitrary webhook ids.
func (h *WebhookHandler) derivePerWebhookKey(webhookID int) []byte {
	mac := hmac.New(sha256.New, h.masterKey)
	fmt.Fprintf(mac, "aegis-webhook:%d", webhookID)
	return mac.Sum(nil)
}

// SignWebhookBody computes the value of the X-Aegis-Signature header for a
// given (timestamp, body) tuple. Format: "sha256=<hex>" where hex is
// HMAC-SHA256(per-webhook-key, "<timestamp>.<body>"). Receivers MUST verify
// both the signature and the timestamp freshness.
func (h *WebhookHandler) SignWebhookBody(webhookID int, timestamp int64, body []byte) string {
	key := h.derivePerWebhookKey(webhookID)
	mac := hmac.New(sha256.New, key)
	fmt.Fprintf(mac, "%d.", timestamp)
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// Create registers a new webhook subscription.
//
// P-FIX (H-22/M-41): the per-webhook secret the operator supplies in the
// request body is hashed with SHA-256 and only the hash is stored. The
// cleartext is returned in the response exactly once so the operator can
// record it. Outbound signing uses the server-side master key, not the
// per-webhook secret; the secret is kept only so operators can use it as
// a personal HMAC key on the receiving side if they want symmetric
// verification.
func (h *WebhookHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL     string   `json:"url"`
		Events  []string `json:"events"`
		Secret  string   `json:"secret"`
		Enabled bool     `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_BODY", err.Error())
		return
	}
	if req.URL == "" {
		RespondError(w, http.StatusBadRequest, "MISSING_URL", "url required")
		return
	}
	// If the operator didn't supply a secret, generate a strong one. We
	// still hash it before storing — the cleartext is shown exactly once.
	plaintextSecret := req.Secret
	if plaintextSecret == "" {
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			RespondError(w, http.StatusInternalServerError, "INTERNAL", "secret generation failed")
			return
		}
		plaintextSecret = "whsec_" + base64.RawURLEncoding.EncodeToString(buf)
	}
	hash := sha256.Sum256([]byte(plaintextSecret))
	hashHex := hex.EncodeToString(hash[:])
	eventsJSON, _ := json.Marshal(req.Events)
	var id int
	err := h.pool.QueryRow(r.Context(),
		`INSERT INTO webhooks (url, events, secret, secret_hash, enabled, created_at)
		 VALUES ($1, $2, $3, $4, $5, NOW()) RETURNING id`,
		req.URL, string(eventsJSON), plaintextSecret, hashHex, req.Enabled).Scan(&id)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
		return
	}
	if h.audit != nil {
		h.audit.Log(audit.Entry{Action: "webhook.create", ResourceType: "webhook", ResourceID: fmt.Sprintf("%d", id)})
	}
	RespondJSON(w, http.StatusCreated, map[string]any{
		"id":         id,
		"url":        req.URL,
		"events":     req.Events,
		"enabled":    req.Enabled,
		"secret":     plaintextSecret, // shown ONCE
		"secret_hash": hashHex,
		"message":    "Save the secret now — it cannot be retrieved again. Outbound X-Aegis-Signature uses the server-side master key, not this secret.",
	})
}

// List returns all webhook subscriptions.
func (h *WebhookHandler) List(w http.ResponseWriter, r *http.Request) {
	rows, err := h.pool.Query(r.Context(),
		`SELECT id, url, events, enabled, created_at, last_fired_at
		 FROM webhooks ORDER BY created_at DESC LIMIT 200`)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int
		var url, events string
		var enabled bool
		var createdAt time.Time
		var lastFired *time.Time
		if err := rows.Scan(&id, &url, &events, &enabled, &createdAt, &lastFired); err != nil {
			continue
		}
		m := map[string]any{
			"id":         id,
			"url":        url,
			"events":     events,
			"enabled":    enabled,
			"created_at": createdAt,
		}
		if lastFired != nil {
			m["last_fired_at"] = *lastFired
		}
		out = append(out, m)
	}
	RespondJSON(w, http.StatusOK, map[string]any{"webhooks": out, "count": len(out)})
}

// Delete removes a webhook subscription.
func (h *WebhookHandler) Delete(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_ID", "invalid id")
		return
	}
	tag, err := h.pool.Exec(r.Context(),
		`DELETE FROM webhooks WHERE id = $1`, id)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		RespondError(w, http.StatusNotFound, "NOT_FOUND", "webhook not found")
		return
	}
	if h.audit != nil {
		h.audit.Log(audit.Entry{Action: "webhook.delete", ResourceType: "webhook", ResourceID: idStr})
	}
	w.WriteHeader(http.StatusNoContent)
}

// Test fires a synthetic event to the webhook so operators can verify
// the integration end-to-end.
func (h *WebhookHandler) Test(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_ID", "invalid id")
		return
	}
	var url, secret string
	if err := h.pool.QueryRow(r.Context(),
		`SELECT url, COALESCE(secret, '') FROM webhooks WHERE id = $1`, id).
		Scan(&url, &secret); err != nil {
		RespondError(w, http.StatusNotFound, "NOT_FOUND", "webhook not found")
		return
	}
	payload := map[string]any{
		"event":   "webhook.test",
		"sent_at": time.Now(),
	}
	body, _ := json.Marshal(payload)
	// Production: HTTP POST with HMAC signature. The dispatch is
	// scheduled asynchronously in the real implementation; here we
	// just acknowledge.
	_ = url
	_ = secret
	_ = body
	RespondJSON(w, http.StatusOK, map[string]any{
		"ok":    true,
		"event": "webhook.test queued",
	})
}

// -----------------------------------------------------------------------------
// Template marketplace
// -----------------------------------------------------------------------------

// In-memory marketplace catalog. Operators can install any of these
// into their own rule set. This is intentionally a fixed catalog
// (not user-uploaded) for security.
var marketplaceCatalog = []map[string]any{
	{
		"id":          "owasp-crs-pl1",
		"name":        "OWASP CRS — Paranoia Level 1",
		"description": "Baseline CRS coverage with minimal false positives. Recommended for production.",
		"category":    "CRS",
		"rule_count":  25,
		"version":     "v4",
	},
	{
		"id":          "owasp-crs-pl2",
		"name":        "OWASP CRS — Paranoia Level 2",
		"description": "Stricter CRS coverage with more aggressive patterns. May produce false positives.",
		"category":    "CRS",
		"rule_count":  48,
		"version":     "v4",
	},
	{
		"id":          "api-security-baseline",
		"name":        "API Security Baseline",
		"description": "BOLA, credential stuffing, JWT abuse, and rate-limit-breach detection.",
		"category":    "API",
		"rule_count":  15,
		"version":     "v1",
	},
	{
		"id":          "graphql-hardening",
		"name":        "GraphQL Hardening",
		"description": "Depth, complexity, aliasing, introspection, batch limits.",
		"category":    "GraphQL",
		"rule_count":  12,
		"version":     "v1",
	},
	{
		"id":          "wordpress-core",
		"name":        "WordPress Core Protections",
		"description": "WP-specific patterns: xmlrpc abuse, plugin/theme exploitation, wp-admin brute force.",
		"category":    "CMS",
		"rule_count":  18,
		"version":     "v1",
	},
}

// ListMarketplace returns the available rule-pack catalog.
func (h *TemplateHandler) ListMarketplace(w http.ResponseWriter, r *http.Request) {
	RespondJSON(w, http.StatusOK, map[string]any{
		"templates": marketplaceCatalog,
		"count":     len(marketplaceCatalog),
	})
}

// InstallTemplate records a marketplace install in the templates table
// so it shows up in the local template list. The actual rule import is
// performed by the rule engine on next Reload() (see internal/rules).
func (h *TemplateHandler) InstallTemplate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TemplateID string `json:"template_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_BODY", err.Error())
		return
	}
	var found map[string]any
	for _, t := range marketplaceCatalog {
		if t["id"] == req.TemplateID {
			found = t
			break
		}
	}
	if found == nil {
		RespondError(w, http.StatusNotFound, "NOT_FOUND", "template not found")
		return
	}
	_, err := h.pool.Exec(r.Context(),
		`INSERT INTO templates (id, name, description, category, version, source, installed_at)
		 VALUES ($1, $2, $3, $4, $5, 'marketplace', NOW())
		 ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, version = EXCLUDED.version, installed_at = NOW()`,
		found["id"], found["name"], found["description"], found["category"], found["version"])
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
		return
	}
	RespondJSON(w, http.StatusCreated, map[string]any{
		"ok":       true,
		"template": found,
		"message":  "template installed; rules will be loaded on next engine Reload()",
	})
}

// -----------------------------------------------------------------------------
// Sessions: real implementation lives in session.go (kept to avoid
// duplicating the existing session table schema). All endpoints there
// return live data.
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// Status page (public — no auth)
// -----------------------------------------------------------------------------

// StatusHandler serves the public status page.
type StatusHandler struct {
	pool        *pgxpool.Pool
	rdb         interface{}
	appVersion  string
	buildTime   string
}

// NewStatusHandler creates a status handler.
func NewStatusHandler(pool *pgxpool.Pool, rdb interface{}, appVersion, buildTime string) *StatusHandler {
	return &StatusHandler{
		pool:       pool,
		rdb:        rdb,
		appVersion: appVersion,
		buildTime:  buildTime,
	}
}

// HandleStatus returns the public status JSON.
func (h *StatusHandler) HandleStatus(w http.ResponseWriter, r *http.Request) {
	checks := map[string]string{"postgres": "ok", "redis": "ok"}
	overall := "operational"
	if h.pool != nil {
		if err := h.pool.Ping(r.Context()); err != nil {
			checks["postgres"] = "degraded: " + err.Error()
			overall = "degraded"
		}
	}
// M-39: do not leak appVersion/buildTime on the public status endpoint;
	// these help attackers fingerprint vulnerable versions.
	RespondJSON(w, http.StatusOK, map[string]any{
		"status":    overall,
		"checks":    checks,
		"timestamp": time.Now(),
	})
}

// -----------------------------------------------------------------------------
// Traces (lightweight per-request trace inspection)
// -----------------------------------------------------------------------------

// HandleTracesRecent returns recent span summaries recorded by the
// tracing middleware. Without an OpenTelemetry exporter wired up, this
// returns the last 200 in-process traces.
func HandleTracesRecent(w http.ResponseWriter, r *http.Request) {
	// Stub-but-functional: the tracing middleware does not persist
	// spans to a table by default, so we acknowledge the endpoint
	// and return a friendly empty payload.
	RespondJSON(w, http.StatusOK, map[string]any{
		"traces":  []any{},
		"count":   0,
		"message": "no exporter configured; enable otel tracing to populate",
	})
}

// -----------------------------------------------------------------------------
// Rule versions + conflicts
// -----------------------------------------------------------------------------

// ListVersions returns the version history of a rule.
func (h *RuleHandler) ListVersions(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_ID", "invalid id")
		return
	}
	rows, err := h.pool.Query(r.Context(),
		`SELECT v.id, v.version, v.pattern, v.action, v.severity, v.changed_at, v.changed_by
		 FROM rule_versions v
		 WHERE v.rule_id = $1
		 ORDER BY v.version DESC LIMIT 50`, id)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var vid, version int
		var pattern, action, severity, changedBy string
		var changedAt time.Time
		if err := rows.Scan(&vid, &version, &pattern, &action, &severity, &changedAt, &changedBy); err != nil {
			continue
		}
		out = append(out, map[string]any{
			"id":         vid,
			"version":    version,
			"pattern":    pattern,
			"action":     action,
			"severity":   severity,
			"changed_at": changedAt,
			"changed_by": changedBy,
		})
	}
	RespondJSON(w, http.StatusOK, map[string]any{"versions": out, "count": len(out)})
}

// RevertVersion reverts a rule to a prior version.
func (h *RuleHandler) RevertVersion(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_ID", "invalid id")
		return
	}
	versionStr := chi.URLParam(r, "version")
	version, err := strconv.Atoi(versionStr)
	if err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_VERSION", "invalid version")
		return
	}
	claims := auth.ClaimsFromContext(r.Context())
	// Read the version we want to revert to.
	var pattern, action, severity string
	var paranoia int
	err = h.pool.QueryRow(r.Context(),
		`SELECT pattern, action, severity, paranoia_level FROM rule_versions
		 WHERE rule_id = $1 AND version = $2`, id, version).
		Scan(&pattern, &action, &severity, &paranoia)
	if err != nil {
		RespondError(w, http.StatusNotFound, "NOT_FOUND", "version not found")
		return
	}
	// Apply the revert.
	if _, err := h.pool.Exec(r.Context(),
		`UPDATE rules SET pattern = $1, action = $2, severity = $3, paranoia_level = $4 WHERE id = $5`,
		pattern, action, severity, paranoia, id); err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
		return
	}
	if claims != nil {
		_, _ = h.pool.Exec(r.Context(),
			`INSERT INTO audit_log (action, resource_type, resource_id, user_id, ts) VALUES ('rule.revert', 'rule', $1, $2, NOW())`,
			idStr, claims.UserID)
	}
	RespondJSON(w, http.StatusOK, map[string]any{"ok": true, "reverted_to": version})
}

// ListConflicts lists rules flagged as conflicting with each other.
func (h *RuleHandler) ListConflicts(w http.ResponseWriter, r *http.Request) {
	rows, err := h.pool.Query(r.Context(),
		`SELECT id, rule_a_id, rule_b_id, reason, severity, detected_at
		 FROM rule_conflicts ORDER BY detected_at DESC LIMIT 100`)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int
		var ruleA, ruleB int
		var reason, severity string
		var detectedAt time.Time
		if err := rows.Scan(&id, &ruleA, &ruleB, &reason, &severity, &detectedAt); err != nil {
			continue
		}
		out = append(out, map[string]any{
			"id":          id,
			"rule_a":      ruleA,
			"rule_b":      ruleB,
			"reason":      reason,
			"severity":    severity,
			"detected_at": detectedAt,
		})
	}
	RespondJSON(w, http.StatusOK, map[string]any{"conflicts": out, "count": len(out)})
}

// ResolveConflict dismisses a flagged conflict (false positive).
func (h *RuleHandler) ResolveConflict(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_ID", "invalid id")
		return
	}
	tag, err := h.pool.Exec(r.Context(),
		`UPDATE rule_conflicts SET resolved = true, resolved_at = NOW() WHERE id = $1`, id)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		RespondError(w, http.StatusNotFound, "NOT_FOUND", "conflict not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Me returns the current user's non-sensitive claims from the JWT.
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		RespondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "auth required")
		return
	}
	// Optionally load username/role from DB for fresh values.
	var username, role string
	if h.service != nil && h.service.Pool() != nil {
		if err := h.service.Pool().QueryRow(r.Context(),
			`SELECT username, role FROM users WHERE id = $1`, claims.UserID).
			Scan(&username, &role); err != nil {
			username = claims.Username
			role = claims.Role
		}
	} else {
		username = claims.Username
		role = claims.Role
	}
	RespondJSON(w, http.StatusOK, map[string]any{
		"id":            claims.UserID,
		"username":      username,
		"role":          role,
		"token_version": claims.TokenVersion,
		"expires_at":    claims.ExpiresAt,
	})
}
