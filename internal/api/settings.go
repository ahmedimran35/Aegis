package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/user/waf/internal/ai"
	"github.com/user/waf/internal/audit"
	"github.com/user/waf/internal/auth"
	"github.com/user/waf/internal/config"
	wafmw "github.com/user/waf/internal/middleware"
	"github.com/user/waf/internal/reputation"
)

// allowedURLSchemes is the allowlist of URL schemes the settings API
// will accept for outbound / upstream URLs. Anything outside this list
// (file://, gopher://, dict://, ldap://, javascript://, data:, etc.) is
// rejected outright to close SSRF and downstream gadget risks.
//
// P-FIX (M-22/M-27): the scheme is parsed FIRST, before any hostname
// resolution, so a request can't probe internal networks via an exotic
// scheme even if the host passes the SSRF check. We also explicitly
// reject udp:// for syslog transports — see siem.go (M-53); tcp+tls
// is required for any production syslog target.
var allowedURLSchemes = map[string]bool{
	"http":   true,
	"https":  true,
	"tcp":    true, // SIEM syslog tcp+tls
	"tls":    true, // SIEM syslog tcp+tls alias
	"tcptls": true, // SIEM syslog tcp+tls alias
	"unix":   true, // SIEM unix socket (loopback only)
}

// allowedSchemeList returns the keys of allowedURLSchemes as a slice
// (used in error messages).
func allowedSchemeList() []string {
	out := make([]string, 0, len(allowedURLSchemes))
	for k := range allowedURLSchemes {
		out = append(out, k)
	}
	return out
}

// validateSettingsURLs checks that AI-related URLs are not pointing to internal/private IPs.
//
// P-FIX (M-22/M-27): scheme allowlist is enforced first, before any
// hostname resolution, so an attacker cannot probe internal IPs via an
// unsupported scheme. We also check the scheme again here to handle
// the SIEM syslog addr (M-53): reject udp:// outright.
func validateSettingsURLs(updates map[string]interface{}) error {
	urlKeys := []string{"ai_nim_base_url", "ai_openrouter_base_url", "alerts_webhook_url", "upstream_url"}
	for _, key := range urlKeys {
		val, ok := updates[key]
		if !ok {
			continue
		}
		urlStr, ok := val.(string)
		if !ok || urlStr == "" {
			continue
		}
		// Parse and validate URL
		u, err := url.Parse(urlStr)
		if err != nil {
			return fmt.Errorf("invalid URL for %s", key)
		}
		// P-FIX (M-22): scheme allowlist BEFORE any further work. If the
		// scheme is missing or not on the list, reject — this is the
		// cheap, always-correct check.
		if u.Scheme == "" {
			return fmt.Errorf("%s: URL scheme missing; allowed schemes: %v", key, allowedSchemeList())
		}
		if !allowedURLSchemes[strings.ToLower(u.Scheme)] {
			return fmt.Errorf("%s: URL scheme %q is not allowed (allowed: %v)", key, u.Scheme, allowedSchemeList())
		}
		host := u.Hostname()
		if host == "" {
			// Bare host:port without scheme (e.g. "127.0.0.1:514")
			h, _, splitErr := net.SplitHostPort(urlStr)
			if splitErr == nil {
				host = h
			}
		}
		if host == "" {
			continue
		}
		// Block private/loopback IPs — literal IP or resolved hostname
		if ip := net.ParseIP(host); ip != nil {
			if isPrivateIP(ip) {
				return fmt.Errorf("%s: URL targets a blocked IP range", key)
			}
		} else {
			// DNS rebinding prevention: resolve hostname and check ALL resolved IPs
			ips, err := net.LookupIP(host)
			if err != nil || len(ips) == 0 {
				return fmt.Errorf("%s: cannot resolve hostname", key)
			}
			for _, ip := range ips {
				if isPrivateIP(ip) {
					return fmt.Errorf("%s: hostname resolves to a blocked IP range", key)
				}
			}
		}
	}

	// Validate SIEM file path is within allowed directories
	if filePath, ok := updates["siem_file_path"]; ok {
		if pathStr, ok := filePath.(string); ok && pathStr != "" {
			if strings.Contains(pathStr, "..") {
				return fmt.Errorf("siem_file_path cannot contain '..'")
			}
			allowed := false
			for _, prefix := range []string{"/var/log/"} {
				if strings.HasPrefix(pathStr, prefix) {
					allowed = true
					break
				}
			}
			if !allowed {
				return fmt.Errorf("siem_file_path must be under /var/log/")
			}
		}
	}

	// P-FIX (M-53): validate the SIEM syslog addr scheme if present.
	if syslogAddr, ok := updates["siem_syslog_addr"]; ok {
		if s, ok := syslogAddr.(string); ok && s != "" {
			if strings.Contains(s, "://") {
				parsed, err := url.Parse(s)
				if err != nil {
					return fmt.Errorf("siem_syslog_addr: invalid URL: %v", err)
				}
				if strings.ToLower(parsed.Scheme) == "udp" {
					return fmt.Errorf("siem_syslog_addr: udp:// rejected; use tcp+tls (tls://) for production")
				}
				if !allowedURLSchemes[strings.ToLower(parsed.Scheme)] {
					return fmt.Errorf("siem_syslog_addr: scheme %q not allowed", parsed.Scheme)
				}
			}
		}
	}

	return nil
}

// validateSettingsTypes checks that setting values have the correct type.
func validateSettingsTypes(updates map[string]interface{}) error {
	for key, value := range updates {
		switch key {
		case "upstream_url", "rate_limit", "bot_detection_mode", "alerts_webhook_url", "alerts_min_severity",
			"ai_nim_api_key", "ai_nim_model", "ai_nim_base_url", "ai_ollama_url", "ai_ollama_model",
			"ai_openrouter_api_key", "ai_openrouter_model", "ai_openrouter_base_url",
			"tls_domains", "tls_email",
			"geoip_blocked", "geoip_db_path", "honeypot_paths", "session_cookie_name", "session_ttl",
			"siem_type", "siem_syslog_addr", "siem_file_path", "siem_format",
			"logging_flush_interval",
			"abuseipdb_api_key",
			"ato_login_paths", "ato_lockout_duration":
			if _, ok := value.(string); !ok {
				return fmt.Errorf("%s must be a string", key)
			}
		case "ai_provider":
			v, ok := value.(string)
			if !ok {
				return fmt.Errorf("ai_provider must be a string", )
			}
			switch v {
			case "nim", "ollama", "openrouter", "auto":
			default:
				return fmt.Errorf("ai_provider must be one of: nim, ollama, openrouter, auto")
			}
		case "ai_failover_threshold":
			if _, ok := value.(float64); !ok {
				return fmt.Errorf("%s must be a number", key)
			}
		case "tls_enabled", "geoip_enabled", "honeypot_enabled", "allowlist_enabled",
			"session_enabled", "siem_enabled", "graphql_enabled", "graphql_block_introspection",
			"reputation_enabled", "ato_enabled":
			if _, ok := value.(bool); !ok {
				return fmt.Errorf("%s must be a boolean", key)
			}
		case "ddos_max_concurrent_conns", "ddos_max_conns_per_ip",
			"ddos_max_new_conns_per_second", "logging_batch_size", "log_retention_days",
			"graphql_max_depth", "graphql_max_complexity", "reputation_threshold",
			"ato_max_attempts_per_ip", "ato_max_usernames_per_ip", "ato_max_ips_per_username":
			v, ok := value.(float64)
			if !ok {
				return fmt.Errorf("%s must be a number", key)
			}
			if v < 0 {
				return fmt.Errorf("%s must be positive", key)
			}
		}
	}
	return nil
}

// redactSecret masks a secret value, showing only the last 4 characters.
func redactSecret(val string) string {
	if val == "" {
		return ""
	}
	if len(val) <= 8 {
		return "****"
	}
	return "****" + val[len(val)-4:]
}

// allowedSettingsKeys is the whitelist of keys that can be updated via the settings API.
var allowedSettingsKeys = map[string]bool{
	"upstream_url":                  true,
	"rate_limit":                    true,
	"bot_detection_mode":            true,
	"alerts_webhook_url":            true,
	"alerts_min_severity":           true,
	"ai_provider":                   true,
	"ai_nim_api_key":                true,
	"ai_nim_model":                  true,
	"ai_nim_base_url":               true,
	"ai_ollama_url":                 true,
	"ai_ollama_model":               true,
	"ai_openrouter_api_key":         true,
	"ai_openrouter_model":           true,
	"ai_openrouter_base_url":        true,
	"ai_failover_threshold":         true,
	"tls_enabled":                   true,
	"tls_domains":                   true,
	"tls_email":                     true,
	"geoip_enabled":                 true,
	"geoip_blocked":                 true,
	"geoip_db_path":                 true,
	"ddos_max_concurrent_conns":     true,
	"ddos_max_conns_per_ip":         true,
	"ddos_max_new_conns_per_second": true,
	"honeypot_enabled":              true,
	"honeypot_paths":                true,
	"allowlist_enabled":             true,
	"session_enabled":               true,
	"session_cookie_name":           true,
	"session_ttl":                   true,
	"siem_enabled":                  true,
	"siem_type":                     true,
	"siem_syslog_addr":              true,
	"siem_file_path":                true,
	"siem_format":                   true,
	"logging_batch_size":            true,
	"logging_flush_interval":        true,
	"log_retention_days":            true,
	"graphql_enabled":               true,
	"graphql_max_depth":             true,
	"graphql_block_introspection":   true,
	"graphql_max_complexity":        true,
	"graphql_allowed_operations":    true,
	"reputation_enabled":           true,
	"abuseipdb_api_key":            true,
	"reputation_threshold":         true,
	"ato_enabled":                  true,
	"ato_login_paths":              true,
	"ato_max_attempts_per_ip":      true,
	"ato_max_usernames_per_ip":     true,
	"ato_max_ips_per_username":     true,
	"ato_lockout_duration":         true,
}

// SettingsHandler handles settings endpoints.
type SettingsHandler struct {
	pool       *pgxpool.Pool
	cfg        *config.Config
	aiRouter   *ai.Router
	audit      *audit.Logger
	repClient  *reputation.Client
	graphqlCfg *wafmw.GraphQLConfig
	mu         sync.RWMutex
}

// NewSettingsHandler creates a new settings handler.
func NewSettingsHandler(pool *pgxpool.Pool, cfg *config.Config, aiRouter *ai.Router, auditLog *audit.Logger, repClient *reputation.Client, graphqlCfg *wafmw.GraphQLConfig) *SettingsHandler {
	return &SettingsHandler{pool: pool, cfg: cfg, aiRouter: aiRouter, audit: auditLog, repClient: repClient, graphqlCfg: graphqlCfg}
}

// LoadDBOverrides applies saved DB settings to the in-memory config and AI router at startup.
func (h *SettingsHandler) LoadDBOverrides() {
	LoadDBConfig(h.pool, h.cfg, h.aiRouter)
}

// LoadDBConfig loads DB config overrides into the in-memory config and AI router.
// Called at startup before the server begins accepting requests.
func LoadDBConfig(pool *pgxpool.Pool, cfg *config.Config, aiRouter *ai.Router) {
	if pool == nil {
		return
	}
	ctx := context.Background()
	rows, err := pool.Query(ctx, `SELECT key, value FROM config`)
	if err != nil {
		return
	}
	defer rows.Close()

	updates := map[string]interface{}{}
	for rows.Next() {
		var key string
		var value json.RawMessage
		if err := rows.Scan(&key, &value); err != nil {
			continue
		}
		var v interface{}
		if err := json.Unmarshal(value, &v); err != nil {
			continue
		}
		updates[key] = v
	}

	if len(updates) > 0 {
		sh := &SettingsHandler{cfg: cfg, aiRouter: aiRouter}
		sh.applyToConfig(updates)
	}
}

// secretSettingsKeys is the set of settings whose values are sensitive.
// When the dashboard GET endpoint returns them, we report only a
// `configured: bool` flag plus the masked value placeholder so the
// plaintext never enters browser memory.
var secretSettingsKeys = map[string]bool{
	"auth_jwt_secret":      true,
	"ai_nim_api_key":       true,
	"ai_openrouter_api_key": true,
	"abuseipdb_api_key":    true,
	"database_url":         true,
	"redis_url":            true,
	"tls_email":            true,
}

// Get handles GET /api/v1/settings — returns merged config (yaml defaults + DB overrides).
// Sensitive keys (api keys, jwt secret, etc.) are NEVER returned in plaintext.
// They are reported as `configured: <bool>` with the value replaced by an
// empty string so the dashboard can render a "•••••• Set" placeholder.
func (h *SettingsHandler) Get(w http.ResponseWriter, r *http.Request) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	// Start with current config values. For sensitive keys we return only a
	// placeholder + `configured: bool` flag; the plaintext stays server-side.
	settings := map[string]interface{}{
		"upstream_url":                 h.cfg.Upstream.URL,
		"rate_limit":                   h.cfg.RateLimit.Default,
		"bot_detection_mode":           h.cfg.BotDetect.Mode,
		"alerts_webhook_url":           h.cfg.Alerts.WebhookURL,
		"alerts_min_severity":          h.cfg.Alerts.MinSeverity,
		"ai_provider":                  h.cfg.AI.Provider,
		"ai_nim_api_key":               secretPlaceholder(h.cfg.AI.NIM.APIKey),
		"ai_nim_api_key_configured":    h.cfg.AI.NIM.APIKey != "",
		"ai_nim_model":                 h.cfg.AI.NIM.Model,
		"ai_nim_base_url":              h.cfg.AI.NIM.BaseURL,
		"ai_ollama_url":                h.cfg.AI.Ollama.URL,
		"ai_ollama_model":              h.cfg.AI.Ollama.Model,
		"ai_failover_threshold":        h.cfg.AI.Failover.Threshold,
		"ai_openrouter_api_key":       secretPlaceholder(h.cfg.AI.OpenRouter.APIKey),
		"ai_openrouter_api_key_configured": h.cfg.AI.OpenRouter.APIKey != "",
		"ai_openrouter_model":         h.cfg.AI.OpenRouter.Model,
		"ai_openrouter_base_url":      h.cfg.AI.OpenRouter.BaseURL,
		"tls_enabled":                  h.cfg.TLS.Enabled,
		"tls_domains":                  strings.Join(h.cfg.TLS.Domains, ", "),
		"tls_email":                    h.cfg.TLS.Email,
		"geoip_enabled":                h.cfg.GeoIP.Enabled,
		"geoip_db_path":                h.cfg.GeoIP.DBPath,
		"geoip_blocked":                strings.Join(h.cfg.GeoIP.Blocked, ", "),
		"ddos_max_concurrent_conns":    h.cfg.DDoS.MaxConcurrentConns,
		"ddos_max_conns_per_ip":        h.cfg.DDoS.MaxConnsPerIP,
		"ddos_max_new_conns_per_second": h.cfg.DDoS.MaxNewConnsPerSecond,
		"honeypot_enabled":             h.cfg.Honeypot.Enabled,
		"honeypot_paths":               strings.Join(h.cfg.Honeypot.Paths, ", "),
		"allowlist_enabled":            h.cfg.Allowlist.Enabled,
		"session_enabled":              h.cfg.Session.Enabled,
		"session_cookie_name":          h.cfg.Session.CookieName,
		"session_ttl":                  h.cfg.Session.TTL.String(),
		"siem_enabled":                 h.cfg.SIEM.Enabled,
		"siem_type":                    h.cfg.SIEM.Type,
		"siem_syslog_addr":             h.cfg.SIEM.SyslogAddr,
		"siem_file_path":               h.cfg.SIEM.FilePath,
		"siem_format":                  h.cfg.SIEM.Format,
		"logging_batch_size":           h.cfg.Logging.BatchSize,
		"logging_flush_interval":       h.cfg.Logging.FlushInterval.String(),
		"graphql_enabled":              h.cfg.GraphQL.Enabled,
		"graphql_max_depth":            h.cfg.GraphQL.MaxDepth,
		"graphql_block_introspection":  h.cfg.GraphQL.BlockIntrospection,
		"graphql_max_complexity":       h.cfg.GraphQL.MaxComplexity,
		"graphql_allowed_operations":   strings.Join(h.cfg.GraphQL.AllowedOperations, ", "),
		"ato_enabled":                  h.cfg.ATO.Enabled,
		"ato_login_paths":              strings.Join(h.cfg.ATO.LoginPaths, ", "),
		"ato_max_attempts_per_ip":      h.cfg.ATO.MaxAttemptsPerIP,
		"ato_max_usernames_per_ip":     h.cfg.ATO.MaxUsernamesPerIP,
		"ato_max_ips_per_username":     h.cfg.ATO.MaxIPsPerUsername,
		"ato_lockout_duration":         h.cfg.ATO.LockoutDuration.String(),
		"reputation_enabled":           h.cfg.Reputation.Enabled,
		"abuseipdb_api_key":            secretPlaceholder(h.cfg.Reputation.AbuseIPDBAPIKey),
		"abuseipdb_api_key_configured": h.cfg.Reputation.AbuseIPDBAPIKey != "",
		"reputation_threshold":         h.cfg.Reputation.AutoBlockThreshold,
	}

	// Merge DB overrides — strip secrets, only report configured state.
	if h.pool != nil {
		ctx := r.Context()
		rows, err := h.pool.Query(ctx, `SELECT key, value FROM config`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var key string
				var value json.RawMessage
				if err := rows.Scan(&key, &value); err != nil {
					continue
				}
				if secretSettingsKeys[key] {
					// Never return the actual value. Report only configured state.
					var raw string
					_ = json.Unmarshal(value, &raw)
					settings[key] = secretPlaceholder(raw)
					settings[key+"_configured"] = raw != ""
					continue
				}
				var v interface{}
				if err := json.Unmarshal(value, &v); err != nil {
					log.Printf("settings: unmarshal: %v", err)
				}
				settings[key] = v
			}
		}
	}

	RespondJSON(w, http.StatusOK, settings)
}

// secretPlaceholder returns a display-safe placeholder for a secret value.
// Empty input returns empty so the UI can decide whether to render the
// "Set" button or hide the field.
func secretPlaceholder(val string) string {
	if val == "" {
		return ""
	}
	return "••••••••"
}

// Update handles PUT /api/v1/settings
func (h *SettingsHandler) Update(w http.ResponseWriter, r *http.Request) {
	if h.pool == nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", "database not available")
		return
	}

	var updates map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	ctx := r.Context()
	for key := range updates {
		if !allowedSettingsKeys[key] {
			RespondError(w, http.StatusBadRequest, "INVALID_KEY", fmt.Sprintf("setting key %q is not allowed", key))
			return
		}
	}
	// P-FIX: reject the *_configured sentinel fields from the update payload.
	// They are read-only markers emitted by GET; a client that supplies them
	// is either confused or malicious.
	for key := range updates {
		if strings.HasSuffix(key, "_configured") {
			RespondError(w, http.StatusBadRequest, "INVALID_KEY", fmt.Sprintf("setting key %q is read-only", key))
			return
		}
	}
	// P-FIX: prevent accidental clearing of secrets. If the dashboard sends
	// the placeholder mask (•) instead of an empty string, treat it as a
	// no-op for sensitive keys so the user can't wipe a stored API key by
	// submitting an unchanged form.
	for key := range updates {
		if !secretSettingsKeys[key] {
			continue
		}
		if v, ok := updates[key].(string); ok {
			if v == "" || strings.HasPrefix(v, "•") {
				delete(updates, key)
			}
		}
	}
	// Validate AI URLs against SSRF
	if err := validateSettingsURLs(updates); err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_URL", err.Error())
		return
	}
	// Validate value types
	if err := validateSettingsTypes(updates); err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_VALUE", err.Error())
		return
	}
	for key, value := range updates {
		valueJSON, _ := json.Marshal(value)
		_, err := h.pool.Exec(ctx,
			`INSERT INTO config (key, value, updated_at) VALUES ($1, $2, NOW())
			 ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()`,
			key, valueJSON)
		if err != nil {
			RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "update setting"))
			return
		}
	}

	// Hot-reload: apply changes to in-memory config
	h.mu.Lock()
	h.applyToConfig(updates)
	h.mu.Unlock()

	if h.audit != nil {
		var uid int
		var uname string
		if c := auth.ClaimsFromContext(r.Context()); c != nil {
			uid, uname = c.UserID, c.Username
		}
		keys := make([]string, 0, len(updates))
		for k := range updates {
			keys = append(keys, k)
		}
		h.audit.LogSettingsChange(uid, uname, "update", map[string]interface{}{"keys": keys}, clientIP(r))
	}

	RespondJSON(w, http.StatusOK, map[string]bool{"updated": true})
}

// applyToConfig applies setting changes to the in-memory config struct.
func (h *SettingsHandler) applyToConfig(updates map[string]interface{}) {
	for key, value := range updates {
		switch key {
		case "upstream_url":
			if v, ok := value.(string); ok {
				h.cfg.Upstream.URL = v
			}
		case "ai_provider":
			if v, ok := value.(string); ok {
				h.cfg.AI.Provider = v
				if h.aiRouter != nil {
					h.aiRouter.SetProvider(v)
				}
			}
		case "ai_nim_api_key":
			if v, ok := value.(string); ok {
				h.cfg.AI.NIM.APIKey = v
				if h.aiRouter != nil {
					h.aiRouter.UpdateNIMConfig(v, "", "")
				}
			}
		case "tls_enabled":
			if v, ok := value.(bool); ok {
				h.cfg.TLS.Enabled = v
			}
		case "tls_domains":
			if v, ok := value.(string); ok {
				h.cfg.TLS.Domains = strings.Split(v, ",")
			}
		case "tls_email":
			if v, ok := value.(string); ok {
				h.cfg.TLS.Email = v
			}
		case "geoip_db_path":
			if v, ok := value.(string); ok {
				h.cfg.GeoIP.DBPath = v
			}
		case "session_cookie_name":
			if v, ok := value.(string); ok {
				h.cfg.Session.CookieName = v
			}
		case "rate_limit":
			if v, ok := value.(string); ok {
				h.cfg.RateLimit.Default = v
			}
		case "bot_detection_mode":
			if v, ok := value.(string); ok {
				h.cfg.BotDetect.Mode = v
			}
		case "alerts_webhook_url":
			if v, ok := value.(string); ok {
				h.cfg.Alerts.WebhookURL = v
			}
		case "alerts_min_severity":
			if v, ok := value.(string); ok {
				h.cfg.Alerts.MinSeverity = v
			}
		case "ai_nim_model":
			if v, ok := value.(string); ok {
				h.cfg.AI.NIM.Model = v
				if h.aiRouter != nil {
					h.aiRouter.UpdateNIMConfig("", v, "")
				}
			}
		case "ai_nim_base_url":
			if v, ok := value.(string); ok {
				h.cfg.AI.NIM.BaseURL = v
				if h.aiRouter != nil {
					h.aiRouter.UpdateNIMConfig("", "", v)
				}
			}
		case "ai_ollama_url":
			if v, ok := value.(string); ok {
				h.cfg.AI.Ollama.URL = v
				if h.aiRouter != nil {
					h.aiRouter.UpdateOllamaConfig(v, "")
				}
			}
		case "ai_ollama_model":
			if v, ok := value.(string); ok {
				h.cfg.AI.Ollama.Model = v
				if h.aiRouter != nil {
					h.aiRouter.UpdateOllamaConfig("", v)
				}
			}
		case "ai_openrouter_api_key":
			if v, ok := value.(string); ok {
				h.cfg.AI.OpenRouter.APIKey = v
				if h.aiRouter != nil {
					h.aiRouter.UpdateOpenRouterConfig(v, "", "")
				}
			}
		case "ai_openrouter_model":
			if v, ok := value.(string); ok {
				h.cfg.AI.OpenRouter.Model = v
				if h.aiRouter != nil {
					h.aiRouter.UpdateOpenRouterConfig("", v, "")
				}
			}
		case "ai_openrouter_base_url":
			if v, ok := value.(string); ok {
				h.cfg.AI.OpenRouter.BaseURL = v
				if h.aiRouter != nil {
					h.aiRouter.UpdateOpenRouterConfig("", "", v)
				}
			}
		case "ai_failover_threshold":
			if v, ok := value.(float64); ok {
				h.cfg.AI.Failover.Threshold = v
			}
		case "geoip_enabled":
			if v, ok := value.(bool); ok {
				h.cfg.GeoIP.Enabled = v
			}
		case "geoip_blocked":
			if v, ok := value.(string); ok {
				h.cfg.GeoIP.Blocked = strings.Split(v, ",")
			}
		case "honeypot_enabled":
			if v, ok := value.(bool); ok {
				h.cfg.Honeypot.Enabled = v
			}
		case "honeypot_paths":
			if v, ok := value.(string); ok {
				h.cfg.Honeypot.Paths = strings.Split(v, ",")
			}
		case "allowlist_enabled":
			if v, ok := value.(bool); ok {
				h.cfg.Allowlist.Enabled = v
			}
		case "session_enabled":
			if v, ok := value.(bool); ok {
				h.cfg.Session.Enabled = v
			}
		case "session_ttl":
			if v, ok := value.(string); ok {
				if d, err := time.ParseDuration(v); err == nil {
					h.cfg.Session.TTL = d
				}
			}
		case "ddos_max_concurrent_conns":
			if v, ok := value.(float64); ok {
				h.cfg.DDoS.MaxConcurrentConns = int(v)
			}
		case "ddos_max_conns_per_ip":
			if v, ok := value.(float64); ok {
				h.cfg.DDoS.MaxConnsPerIP = int(v)
			}
		case "ddos_max_new_conns_per_second":
			if v, ok := value.(float64); ok {
				h.cfg.DDoS.MaxNewConnsPerSecond = int(v)
			}
		case "siem_enabled":
			if v, ok := value.(bool); ok {
				h.cfg.SIEM.Enabled = v
			}
		case "siem_type":
			if v, ok := value.(string); ok {
				h.cfg.SIEM.Type = v
			}
		case "siem_syslog_addr":
			if v, ok := value.(string); ok {
				h.cfg.SIEM.SyslogAddr = v
			}
		case "siem_file_path":
			if v, ok := value.(string); ok {
				h.cfg.SIEM.FilePath = v
			}
		case "siem_format":
			if v, ok := value.(string); ok {
				h.cfg.SIEM.Format = v
			}
		case "logging_batch_size":
			if v, ok := value.(float64); ok {
				h.cfg.Logging.BatchSize = int(v)
			}
		case "logging_flush_interval":
			if v, ok := value.(string); ok {
				if d, err := time.ParseDuration(v); err == nil {
					h.cfg.Logging.FlushInterval = d
				}
			}
		case "ato_enabled":
			if v, ok := value.(bool); ok {
				h.cfg.ATO.Enabled = v
			}
		case "ato_login_paths":
			if v, ok := value.(string); ok {
				h.cfg.ATO.LoginPaths = strings.Split(v, ",")
			}
		case "ato_max_attempts_per_ip":
			if v, ok := value.(float64); ok {
				h.cfg.ATO.MaxAttemptsPerIP = int(v)
			}
		case "ato_max_usernames_per_ip":
			if v, ok := value.(float64); ok {
				h.cfg.ATO.MaxUsernamesPerIP = int(v)
			}
		case "ato_max_ips_per_username":
			if v, ok := value.(float64); ok {
				h.cfg.ATO.MaxIPsPerUsername = int(v)
			}
		case "ato_lockout_duration":
			if v, ok := value.(string); ok {
				if d, err := time.ParseDuration(v); err == nil {
					h.cfg.ATO.LockoutDuration = d
				}
			}
		case "graphql_enabled":
			if v, ok := value.(bool); ok {
				h.cfg.GraphQL.Enabled = v
			}
			h.syncGraphQLConfig()
		case "graphql_max_depth":
			if v, ok := value.(float64); ok {
				h.cfg.GraphQL.MaxDepth = int(v)
			}
			h.syncGraphQLConfig()
		case "graphql_block_introspection":
			if v, ok := value.(bool); ok {
				h.cfg.GraphQL.BlockIntrospection = v
			}
			h.syncGraphQLConfig()
		case "graphql_max_complexity":
			if v, ok := value.(float64); ok {
				h.cfg.GraphQL.MaxComplexity = int(v)
			}
			h.syncGraphQLConfig()
		case "graphql_allowed_operations":
			if v, ok := value.(string); ok {
				if v == "" {
					h.cfg.GraphQL.AllowedOperations = nil
				} else {
					h.cfg.GraphQL.AllowedOperations = strings.Split(v, ",")
				}
			}
			h.syncGraphQLConfig()
		case "reputation_enabled":
			if v, ok := value.(bool); ok {
				h.cfg.Reputation.Enabled = v
				if h.repClient != nil {
					h.repClient.SetEnabled(v)
				}
			}
		case "abuseipdb_api_key":
			if v, ok := value.(string); ok {
				h.cfg.Reputation.AbuseIPDBAPIKey = v
				if h.repClient != nil {
					h.repClient.SetAPIKey(v)
				}
			}
		case "reputation_threshold":
			if v, ok := value.(float64); ok {
				h.cfg.Reputation.AutoBlockThreshold = int(v)
			}
		}
	}
}

// syncGraphQLConfig pushes current config.GraphQL values to the runtime GraphQL middleware config.
func (h *SettingsHandler) syncGraphQLConfig() {
	if h.graphqlCfg != nil {
		h.graphqlCfg.UpdateConfig(
			h.cfg.GraphQL.Enabled,
			h.cfg.GraphQL.MaxDepth,
			h.cfg.GraphQL.MaxComplexity,
			h.cfg.GraphQL.BlockIntrospection,
			h.cfg.GraphQL.AllowedOperations,
		)
	}
}
