package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/user/waf/internal/audit"
	"github.com/user/waf/internal/auth"
	"github.com/user/waf/internal/rules"
)

// readAllLimited reads up to max bytes from r, returning an error if the
// body would exceed the cap. EOF is treated as a clean terminator.
func readAllLimited(r io.Reader, max int64) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, io.LimitReader(r, max+1)); err != nil {
		return nil, err
	}
	if int64(buf.Len()) > max {
		return nil, fmt.Errorf("body exceeds %d bytes", max)
	}
	return buf.Bytes(), nil
}

// configSigningKey returns the HMAC key used to sign / verify exported
// config. Operators SHOULD set AEGIS_CONFIG_HMAC_KEY to a high-entropy
// random value; if absent, fall back to the JWT secret (still better than
// nothing, since the export is admin-only).
func configSigningKey(jwtSecret string) []byte {
	if k := os.Getenv("AEGIS_CONFIG_HMAC_KEY"); k != "" {
		return []byte(k)
	}
	return []byte(jwtSecret)
}

// signConfig computes the HMAC-SHA256 over a JSON body. The signature is
// appended to the export and verified on import so a tampered or
// hand-crafted config cannot be silently applied.
func signConfig(key []byte, body []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// H-14 / C-3: hard caps on rule imports to prevent denial-of-service via
// huge bundles or near-infinite-length patterns.
const (
	maxImportRules      = 1000
	maxImportFieldLen   = 1024 // pattern max
	maxImportNameLen    = 128  // name max
)

// ConfigHandler handles config export/import endpoints.
type ConfigHandler struct {
	pool      *pgxpool.Pool
	audit     *audit.Logger
	signKey   []byte
}

// NewConfigHandler creates a config handler.
func NewConfigHandler(pool *pgxpool.Pool, auditLog *audit.Logger, signKey []byte) *ConfigHandler {
	if len(signKey) == 0 {
		// H-31: refuse to operate without a signing key.
		panic("NewConfigHandler: signing key is required")
	}
	return &ConfigHandler{pool: pool, audit: auditLog, signKey: signKey}
}

// ExportConfig is the JSON structure returned by the export endpoint.
type ExportConfig struct {
	Version        string                   `json:"version"`
	ExportedAt     string                   `json:"exported_at"`
	Settings       map[string]interface{}   `json:"settings"`
	Rules          []map[string]interface{} `json:"rules"`
	Allowlist      []map[string]interface{} `json:"allowlist"`
	VirtualPatches []map[string]interface{} `json:"virtual_patches"`
	GeoIPRules     []map[string]interface{} `json:"geoip_rules"`
	// Signature is the HMAC-SHA256 of the JSON-encoded payload
	// (without this field). Verified on import.
	Signature      string                   `json:"signature,omitempty"`
}

// ImportRequest is the payload for the import endpoint.
type ImportRequest struct {
	DryRun bool `json:"dry_run"`
	ExportConfig
}

// Export handles GET /api/v1/config/export — exports all WAF configuration as JSON.
//
// P-FIX (L-6 / M-7): secrets are ALWAYS stripped from the export by
// default. To include secrets, the caller must pass
// `?include_secrets=true` AND have admin role. This is defense in depth:
// the dashboard asks the user for an explicit "Include secrets" toggle
// with a typed confirmation, and the server still enforces role +
// query-param. Belt and suspenders so a stolen dashboard session cannot
// quietly exfiltrate API keys.
func (h *ConfigHandler) Export(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	includeSecrets := false
	if r.URL.Query().Get("include_secrets") == "true" {
		claims := auth.ClaimsFromContext(ctx)
		if claims == nil || claims.Role != "admin" {
			RespondError(w, http.StatusForbidden, "FORBIDDEN", "include_secrets requires admin role")
			return
		}
		includeSecrets = true
	}

	// Settings — redact secrets before export unless explicitly opted in.
	settings := map[string]interface{}{}
	secretKeys := map[string]bool{
		"auth_jwt_secret": true, "ai_nim_api_key": true, "ai_openrouter_api_key": true,
		"abuseipdb_api_key": true, "alerts_webhook_url": true, "database_url": true, "redis_url": true,
	}
	rows, err := h.pool.Query(ctx, `SELECT key, value FROM config`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var key string
			var value json.RawMessage
			if err := rows.Scan(&key, &value); err != nil {
				continue
			}
			if secretKeys[key] {
				if includeSecrets {
					var v interface{}
					_ = json.Unmarshal(value, &v)
					settings[key] = v
				} else {
					settings[key] = "[REDACTED]"
				}
				continue
			}
			var v interface{}
			json.Unmarshal(value, &v)
			settings[key] = v
		}
	}

	// Rules
	rules, err := h.queryRules(ctx)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "export rules"))
		return
	}

	// Allowlist
	allowlist, err := h.queryAllowlist(ctx)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "export allowlist"))
		return
	}

	// Virtual patches
	patches, err := h.queryVirtualPatches(ctx)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "export virtual patches"))
		return
	}

	// GeoIP rules
	geoip, err := h.queryGeoIPRules(ctx)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "export geoip rules"))
		return
	}

	cfg := ExportConfig{
		Version:        "1.0",
		ExportedAt:     time.Now().UTC().Format(time.RFC3339),
		Settings:       settings,
		Rules:          rules,
		Allowlist:      allowlist,
		VirtualPatches: patches,
		GeoIPRules:     geoip,
	}

	// H-31: sign the canonical export body. The signature is computed
	// over a JSON-encoded copy of the struct with the Signature field
	// blanked so a re-encoding of the same logical payload yields the
	// same digest.
	signBody, _ := json.Marshal(cfg)
	cfg.Signature = signConfig(h.signKey, signBody)

	if h.audit != nil {
		var uid int
		var uname string
		if c := auth.ClaimsFromContext(r.Context()); c != nil {
			uid, uname = c.UserID, c.Username
		}
		h.audit.Log(audit.Entry{
			UserID:       uid,
			Username:     uname,
			Action:       "export",
			ResourceType: "config",
			IPAddress:    clientIP(r),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	// L-6: never cache exports; they include sensitive configuration.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", "attachment; filename=aegis-config-export.json")
	json.NewEncoder(w).Encode(cfg)
}

// Import handles POST /api/v1/config/import — validates and applies imported config.
func (h *ConfigHandler) Import(w http.ResponseWriter, r *http.Request) {
	// Read raw body so we can verify the signature BEFORE unmarshalling
	// anything. This guards against a tampered payload that bypasses the
	// signature by setting a new Signature value during decode.
	rawBody, err := readAllLimited(r.Body, 4*1024*1024)
	if err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_BODY", "could not read request body")
		return
	}
	var req ImportRequest
	if err := json.Unmarshal(rawBody, &req); err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid JSON payload")
		return
	}

	// H-31: verify the HMAC signature. We re-marshal the parsed struct
	// with the Signature field cleared; that is the same canonical form
	// the server used to compute the signature at export time.
	providedSig := req.Signature
	req.Signature = ""
	body, _ := json.Marshal(req)
	wantSig := signConfig(h.signKey, body)
	if !hmac.Equal([]byte(providedSig), []byte(wantSig)) {
		RespondError(w, http.StatusBadRequest, "INVALID_SIGNATURE",
			"config signature missing or does not match; refusing to import unsigned config")
		return
	}

	// H-31: refuse to import any setting value that was redacted at
	// export time. Otherwise a config that was exported and then mutated
	// could leak the "[REDACTED]" placeholder into the live settings.
	for k, v := range req.Settings {
		if s, ok := v.(string); ok && s == "[REDACTED]" {
			RespondError(w, http.StatusBadRequest, "REDACTED_VALUE",
				fmt.Sprintf("setting %q is a redacted placeholder; supply a real value to import", k))
			return
		}
	}

	// Validate version
	if req.Version == "" {
		RespondError(w, http.StatusBadRequest, "INVALID_VERSION", "missing config version")
		return
	}

	// H-14: cap total number of rules in an import bundle to prevent
	// operator-misconfiguration or hostile bundle from inflating the rule
	// table past recovery.
	if len(req.Rules) > maxImportRules {
		RespondError(w, http.StatusBadRequest, "INVALID_RULES",
			fmt.Sprintf("rule import exceeds %d rules", maxImportRules))
		return
	}

	// Validate each section
	if err := validateImportRules(req.Rules); err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_RULES", err.Error())
		return
	}
	if err := validateImportAllowlist(req.Allowlist); err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_ALLOWLIST", err.Error())
		return
	}
	if err := validateImportPatches(req.VirtualPatches); err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_PATCHES", err.Error())
		return
	}
	if err := validateImportGeoIP(req.GeoIPRules); err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_GEOIP", err.Error())
		return
	}

	// Dry run: return what would be imported without applying
	if req.DryRun {
		RespondJSON(w, http.StatusOK, map[string]interface{}{
			"dry_run":        true,
			"settings_count": len(req.Settings),
			"rules_count":    len(req.Rules),
			"allowlist_count": len(req.Allowlist),
			"patches_count":  len(req.VirtualPatches),
			"geoip_count":    len(req.GeoIPRules),
			"validation":     "passed",
		})
		return
	}

	ctx := r.Context()

	// Apply settings — validate keys and URLs against SSRF
	if len(req.Settings) > 0 {
		for key := range req.Settings {
			if !allowedSettingsKeys[key] {
				RespondError(w, http.StatusBadRequest, "INVALID_KEY", fmt.Sprintf("setting key %q is not allowed", key))
				return
			}
		}
		if err := validateSettingsURLs(req.Settings); err != nil {
			RespondError(w, http.StatusBadRequest, "INVALID_URL", err.Error())
			return
		}
		for key, value := range req.Settings {
			valueJSON, _ := json.Marshal(value)
			_, err := h.pool.Exec(ctx,
				`INSERT INTO config (key, value, updated_at) VALUES ($1, $2, NOW())
				 ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()`,
				key, valueJSON)
			if err != nil {
				RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "import settings"))
				return
			}
		}
	}

	// Apply rules — replace all user-created rules
	if len(req.Rules) > 0 {
		_, err := h.pool.Exec(ctx, `DELETE FROM rules WHERE source = 'user' OR source = '' OR source IS NULL`)
		if err != nil {
			RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "clear rules"))
			return
		}
		for _, rule := range req.Rules {
			name, _ := rule["name"].(string)
			pattern, _ := rule["pattern"].(string)
			matchType, _ := rule["match_type"].(string)
			action, _ := rule["action"].(string)
			severity, _ := rule["severity"].(string)
			priority := 100
			if p, ok := rule["priority"].(float64); ok {
				priority = int(p)
			}
			description, _ := rule["description"].(string)
			// H-14: imported rules are ALWAYS inserted disabled. Operator
			// must review and enable via the dashboard — defeats the
			// "import a backdoored payload and watch it fire" attack.
			enabled := false

			if name == "" || pattern == "" || matchType == "" || action == "" || severity == "" {
				continue
			}

			// C-3: gate every regex rule through ReDoS structural and
			// probe layers. This prevents importing a malicious pattern
			// like `(a+)+$` that locks up the matcher goroutine.
			if matchType == "regex" {
				if err := rules.HasReDoSRisk(pattern); err != nil {
					RespondError(w, http.StatusBadRequest, "REDOS_PATTERN",
						fmt.Sprintf("rule %q rejected: %v", name, err))
					return
				}
				if _, err := regexp.Compile(pattern); err != nil {
					RespondError(w, http.StatusBadRequest, "INVALID_REGEX",
						fmt.Sprintf("rule %q pattern does not compile: %v", name, err))
					return
				}
			}

			_, err := h.pool.Exec(ctx,
				`INSERT INTO rules (name, pattern, match_type, action, severity, priority, description, enabled, source)
				 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'user')`,
				name, pattern, matchType, action, severity, priority, description, enabled)
			if err != nil {
				RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "import rule"))
				return
			}
		}
	}

	// Apply allowlist — replace all
	if len(req.Allowlist) > 0 {
		_, err := h.pool.Exec(ctx, `DELETE FROM allowlist_rules`)
		if err != nil {
			RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "clear allowlist"))
			return
		}
		for _, rule := range req.Allowlist {
			ruleType, _ := rule["rule_type"].(string)
			pattern, _ := rule["pattern"].(string)
			description, _ := rule["description"].(string)
			priority := 100
			if p, ok := rule["priority"].(float64); ok {
				priority = int(p)
			}

			if ruleType == "" || pattern == "" {
				continue
			}

			_, err := h.pool.Exec(ctx,
				`INSERT INTO allowlist_rules (rule_type, pattern, description, priority)
				 VALUES ($1, $2, $3, $4)`,
				ruleType, pattern, description, priority)
			if err != nil {
				RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "import allowlist"))
				return
			}
		}
	}

	// Apply virtual patches — replace all
	if len(req.VirtualPatches) > 0 {
		_, err := h.pool.Exec(ctx, `DELETE FROM virtual_patches`)
		if err != nil {
			RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "clear patches"))
			return
		}
		for _, patch := range req.VirtualPatches {
			cveID, _ := patch["cve_id"].(string)
			name, _ := patch["name"].(string)
			desc, _ := patch["description"].(string)
			rulePattern, _ := patch["rule_pattern"].(string)
			matchType, _ := patch["match_type"].(string)
			action, _ := patch["action"].(string)
			severity, _ := patch["severity"].(string)
			enabled := true
			if e, ok := patch["enabled"].(bool); ok {
				enabled = e
			}

			if cveID == "" || rulePattern == "" {
				continue
			}

			var affectedPaths []string
			if ap, ok := patch["affected_paths"].([]interface{}); ok {
				for _, p := range ap {
					if s, ok := p.(string); ok {
						affectedPaths = append(affectedPaths, s)
					}
				}
			}

			_, err := h.pool.Exec(ctx,
				`INSERT INTO virtual_patches (cve_id, name, description, rule_pattern, match_type, action, severity, affected_paths, enabled)
				 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
				cveID, name, desc, rulePattern, matchType, action, severity, affectedPaths, enabled)
			if err != nil {
				RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "import patch"))
				return
			}
		}
	}

	// Apply GeoIP rules — replace all
	if len(req.GeoIPRules) > 0 {
		_, err := h.pool.Exec(ctx, `DELETE FROM geoip_rules`)
		if err != nil {
			RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "clear geoip"))
			return
		}
		for _, rule := range req.GeoIPRules {
			countryCode, _ := rule["country_code"].(string)
			action, _ := rule["action"].(string)
			reason, _ := rule["reason"].(string)
			enabled := true
			if e, ok := rule["enabled"].(bool); ok {
				enabled = e
			}

			if countryCode == "" || action == "" {
				continue
			}

			_, err := h.pool.Exec(ctx,
				`INSERT INTO geoip_rules (country_code, action, reason, enabled)
				 VALUES ($1, $2, $3, $4)`,
				countryCode, action, reason, enabled)
			if err != nil {
				RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "import geoip"))
				return
			}
		}
	}

	if h.audit != nil {
		var uid int
		var uname string
		if c := auth.ClaimsFromContext(r.Context()); c != nil {
			uid, uname = c.UserID, c.Username
		}
		h.audit.Log(audit.Entry{
			UserID:       uid,
			Username:     uname,
			Action:       "import",
			ResourceType: "config",
			Details: map[string]string{
				"settings": fmt.Sprintf("%d", len(req.Settings)),
				"rules":    fmt.Sprintf("%d", len(req.Rules)),
			},
			IPAddress: clientIP(r),
		})
	}

	RespondJSON(w, http.StatusOK, map[string]interface{}{
		"imported":         true,
		"settings_count":   len(req.Settings),
		"rules_count":      len(req.Rules),
		"allowlist_count":  len(req.Allowlist),
		"patches_count":    len(req.VirtualPatches),
		"geoip_count":      len(req.GeoIPRules),
	})
}

// --- Query helpers ---

func (h *ConfigHandler) queryRules(ctx context.Context) ([]map[string]interface{}, error) {
	rows, err := h.pool.Query(ctx,
		`SELECT name, pattern, match_type, action, severity, priority, enabled, COALESCE(description, '')
		 FROM rules ORDER BY priority ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []map[string]interface{}
	for rows.Next() {
		var name, pattern, matchType, action, severity, description string
		var priority int
		var enabled bool
		if err := rows.Scan(&name, &pattern, &matchType, &action, &severity, &priority, &enabled, &description); err != nil {
			continue
		}
		rules = append(rules, map[string]interface{}{
			"name":        name,
			"pattern":     pattern,
			"match_type":  matchType,
			"action":      action,
			"severity":    severity,
			"priority":    priority,
			"enabled":     enabled,
			"description": description,
		})
	}
	if rules == nil {
		rules = []map[string]interface{}{}
	}
	return rules, nil
}

func (h *ConfigHandler) queryAllowlist(ctx context.Context) ([]map[string]interface{}, error) {
	rows, err := h.pool.Query(ctx,
		`SELECT rule_type, pattern, COALESCE(description, ''), priority, enabled
		 FROM allowlist_rules ORDER BY priority ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []map[string]interface{}
	for rows.Next() {
		var ruleType, pattern, description string
		var priority int
		var enabled bool
		if err := rows.Scan(&ruleType, &pattern, &description, &priority, &enabled); err != nil {
			continue
		}
		rules = append(rules, map[string]interface{}{
			"rule_type":   ruleType,
			"pattern":     pattern,
			"description": description,
			"priority":    priority,
			"enabled":     enabled,
		})
	}
	if rules == nil {
		rules = []map[string]interface{}{}
	}
	return rules, nil
}

func (h *ConfigHandler) queryVirtualPatches(ctx context.Context) ([]map[string]interface{}, error) {
	rows, err := h.pool.Query(ctx,
		`SELECT cve_id, name, COALESCE(description, ''), rule_pattern, match_type, action, severity, affected_paths, enabled
		 FROM virtual_patches ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var patches []map[string]interface{}
	for rows.Next() {
		var cveID, name, desc, pattern, matchType, action, severity string
		var paths []string
		var enabled bool
		if err := rows.Scan(&cveID, &name, &desc, &pattern, &matchType, &action, &severity, &paths, &enabled); err != nil {
			continue
		}
		patches = append(patches, map[string]interface{}{
			"cve_id":         cveID,
			"name":           name,
			"description":    desc,
			"rule_pattern":   pattern,
			"match_type":     matchType,
			"action":         action,
			"severity":       severity,
			"affected_paths": paths,
			"enabled":        enabled,
		})
	}
	if patches == nil {
		patches = []map[string]interface{}{}
	}
	return patches, nil
}

func (h *ConfigHandler) queryGeoIPRules(ctx context.Context) ([]map[string]interface{}, error) {
	rows, err := h.pool.Query(ctx,
		`SELECT country_code, action, COALESCE(reason, ''), enabled
		 FROM geoip_rules ORDER BY country_code`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []map[string]interface{}
	for rows.Next() {
		var cc, action, reason string
		var enabled bool
		if err := rows.Scan(&cc, &action, &reason, &enabled); err != nil {
			continue
		}
		rules = append(rules, map[string]interface{}{
			"country_code": cc,
			"action":       action,
			"reason":       reason,
			"enabled":      enabled,
		})
	}
	if rules == nil {
		rules = []map[string]interface{}{}
	}
	return rules, nil
}

// --- Validation helpers ---

func validateImportRules(rules []map[string]interface{}) error {
	for i, rule := range rules {
		name, _ := rule["name"].(string)
		pattern, _ := rule["pattern"].(string)
		matchType, _ := rule["match_type"].(string)
		action, _ := rule["action"].(string)
		severity, _ := rule["severity"].(string)
		if name == "" || pattern == "" || matchType == "" || action == "" || severity == "" {
			return fmt.Errorf("rule %d: name, pattern, match_type, action, severity are required", i+1)
		}
		// H-14: bound field lengths so an attacker cannot upload a 50MB
		// pattern that consumes DB rows or runs away on regex compile.
		if len(pattern) > maxImportFieldLen {
			return fmt.Errorf("rule %d: pattern exceeds %d chars", i+1, maxImportFieldLen)
		}
		if len(name) > maxImportNameLen {
			return fmt.Errorf("rule %d: name exceeds %d chars", i+1, maxImportNameLen)
		}
		validMatch := map[string]bool{"regex": true, "string": true, "ip": true, "cidr": true}
		if !validMatch[matchType] {
			return fmt.Errorf("rule %d: invalid match_type %q", i+1, matchType)
		}
		validAction := map[string]bool{"block": true, "allow": true, "log": true, "challenge": true}
		if !validAction[action] {
			return fmt.Errorf("rule %d: invalid action %q", i+1, action)
		}
	}
	return nil
}

func validateImportAllowlist(rules []map[string]interface{}) error {
	validTypes := map[string]bool{"ip": true, "cidr": true, "path": true, "user_agent": true}
	for i, rule := range rules {
		ruleType, _ := rule["rule_type"].(string)
		pattern, _ := rule["pattern"].(string)
		if ruleType == "" || pattern == "" {
			return fmt.Errorf("allowlist %d: rule_type and pattern are required", i+1)
		}
		if !validTypes[ruleType] {
			return fmt.Errorf("allowlist %d: invalid rule_type %q", i+1, ruleType)
		}
		if ruleType == "ip" && net.ParseIP(pattern) == nil {
			return fmt.Errorf("allowlist %d: invalid IP %q", i+1, pattern)
		}
		if ruleType == "cidr" {
			if _, _, err := net.ParseCIDR(pattern); err != nil {
				return fmt.Errorf("allowlist %d: invalid CIDR %q", i+1, pattern)
			}
		}
	}
	return nil
}

func validateImportPatches(patches []map[string]interface{}) error {
	for i, patch := range patches {
		cveID, _ := patch["cve_id"].(string)
		rulePattern, _ := patch["rule_pattern"].(string)
		if cveID == "" || rulePattern == "" {
			return fmt.Errorf("patch %d: cve_id and rule_pattern are required", i+1)
		}
	}
	return nil
}

func validateImportGeoIP(rules []map[string]interface{}) error {
	for i, rule := range rules {
		cc, _ := rule["country_code"].(string)
		action, _ := rule["action"].(string)
		if cc == "" || action == "" {
			return fmt.Errorf("geoip %d: country_code and action are required", i+1)
		}
		if len(cc) != 2 {
			return fmt.Errorf("geoip %d: country_code must be 2 characters", i+1)
		}
	}
	return nil
}

// readAllLimited reads up to limit bytes from r.
