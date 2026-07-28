package config

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server             ServerConfig             `yaml:"server"`
	Upstream           UpstreamConfig           `yaml:"upstream"`
	AI                 AIConfig                 `yaml:"ai"`
	RateLimit          RateLimitConfig          `yaml:"rate_limit"`
	ThreatFeed         ThreatFeedConfig         `yaml:"threat_feed"`
	WSGuard            WSGuardConfig            `yaml:"ws_guard"`
	CRSUpdate          CRSUpdateConfig          `yaml:"crs_update"`
	AnomalyStats       AnomalyStatsConfig       `yaml:"anomaly_stats"`
	Redis              RedisConfig              `yaml:"redis"`
	Database           DatabaseConfig           `yaml:"database"`
	Logging            LoggingConfig            `yaml:"logging"`
	Auth               AuthConfig               `yaml:"auth"`
	BotDetect          BotDetectConfig          `yaml:"bot_detection"`
	Alerts             AlertsConfig             `yaml:"alerts"`
	TLS                TLSConfig                `yaml:"tls"`
	GeoIP              GeoIPConfig              `yaml:"geoip"`
	SIEM               SIEMConfig               `yaml:"siem"`
	DDoS               DDoSConfig               `yaml:"ddos"`
	Honeypot           HoneypotConfig           `yaml:"honeypot"`
	Allowlist          AllowlistConfig          `yaml:"allowlist"`
	Session            SessionConfig            `yaml:"session"`
	Rules              RulesConfig              `yaml:"rules"`
	ResponseInspect    ResponseInspectConfig    `yaml:"response_inspect"`
	BodyInspect        BodyInspectConfig        `yaml:"body_inspect"`
	BruteForce         BruteForceConfig         `yaml:"brute_force"`
	Reputation         ReputationConfig         `yaml:"reputation"`
	GraphQL            GraphQLConfig            `yaml:"graphql"`
	ATO                ATOConfig                `yaml:"ato"`
	LibInjection       LibInjectionConfig       `yaml:"libinjection"`
	SlowDoS            SlowDoSConfig            `yaml:"slow_dos"`
	BehavioralBot      BehavioralBotConfig      `yaml:"behavioral_bot"`
	BOLA               BOLAConfig               `yaml:"bola"`
	CredentialStuffing CredentialStuffingConfig `yaml:"credential_stuffing"`
	CSPNonce           CSPNonceConfig           `yaml:"csp_nonce"`
	ShadowAPI          ShadowAPIDiscoveryConfig `yaml:"shadow_api"`
}

type LibInjectionConfig struct {
	Enabled   bool `yaml:"enabled"`
	Threshold int  `yaml:"threshold"` // anomaly points to block, default 2
}

type SlowDoSConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Window1m  int    `yaml:"window_1m"`
	Window5m  int    `yaml:"window_5m"`
	Window15m int    `yaml:"window_15m"`
	Action    string `yaml:"action"`
}

type BehavioralBotConfig struct {
	Enabled        bool `yaml:"enabled"`
	ScoreThreshold int  `yaml:"score_threshold"`
}

type BOLAConfig struct {
	Enabled          bool    `yaml:"enabled"`
	PathPattern      string  `yaml:"path_pattern"`
	AnomalyThreshold float64 `yaml:"anomaly_threshold"`
}

type CredentialStuffingConfig struct {
	Enabled     bool          `yaml:"enabled"`
	Window      time.Duration `yaml:"window"`
	MinIPs      int           `yaml:"min_ips"`
	MinAttempts int           `yaml:"min_attempts"`
}

type CSPNonceConfig struct {
	Enabled bool `yaml:"enabled"`
}

type ShadowAPIDiscoveryConfig struct {
	Enabled     bool  `yaml:"enabled"`
	MinReqCount int64 `yaml:"min_req_count"`
}

// ThreatFeedConfig controls the free community blocklist puller.
type ThreatFeedConfig struct {
	Enabled    bool     `yaml:"enabled"`     // puller on/off
	AutoBlock  bool     `yaml:"auto_block"`  // block (true) vs only flag (false)
	Sources    []string `yaml:"sources"`     // optional override; empty = defaults
}

// WSGuardConfig controls WebSocket protection.
type WSGuardConfig struct {
	Enabled              bool     `yaml:"enabled"`
	MaxMessageBytes      int64    `yaml:"max_message_bytes"`
	HandshakeTimeoutMs   int      `yaml:"handshake_timeout_ms"`
	AllowedOrigins       []string `yaml:"allowed_origins"`
	MaxMessagesPerMin    int      `yaml:"max_messages_per_min"`
	MaxConnectionsPerIP  int      `yaml:"max_connections_per_ip"`
}

// CRSUpdateConfig controls the free OWASP CRS auto-updater.
type CRSUpdateConfig struct {
	Enabled   bool          `yaml:"enabled"`
	Interval  time.Duration `yaml:"interval"`
	GitHubRef string        `yaml:"github_ref"` // e.g. "main", "v4.0.0"
}

// AnomalyStatsConfig controls the free statistical anomaly scoring engine.
type AnomalyStatsConfig struct {
	Enabled           bool    `yaml:"enabled"`
	FailClosed        bool    `yaml:"fail_closed"`
	EntropyThreshold  float64 `yaml:"entropy_threshold"`
	RequestRateZScore float64 `yaml:"request_rate_zscore"`
}

type AuthConfig struct {
	JWTSecret string `yaml:"jwt_secret"`
	TTL       string `yaml:"ttl"`         // optional JWT TTL override, e.g. "1h"
	SCIMOrgID int    `yaml:"scim_org_id"` // org_id assigned to SCIM-provisioned users
}

type BotDetectConfig struct {
	Mode string `yaml:"mode"` // block, log, off
}

type AlertsConfig struct {
	WebhookURL  string `yaml:"webhook_url"`
	MinSeverity string `yaml:"min_severity"`
}

type ServerConfig struct {
	Listen      string   `yaml:"listen"`
	CORSOrigins []string `yaml:"cors_origins"`
}

type UpstreamConfig struct {
	URL string `yaml:"url"`
}

type AIConfig struct {
	Provider   string           `yaml:"provider"` // "nim", "ollama", "openrouter", or "auto" (default: nim primary, ollama fallback)
	NIM        NIMConfig        `yaml:"nim"`
	Ollama     OllamaConfig     `yaml:"ollama"`
	OpenRouter OpenRouterConfig `yaml:"openrouter"`
	Failover   FailoverConfig   `yaml:"failover"`
	Classify   AIClassifyConfig `yaml:"classify"`
}

type AIClassifyConfig struct {
	FailClosed      bool          `yaml:"fail_closed"`       // block requests if AI unavailable (default: false = fail-open)
	FailClosedPaths []string      `yaml:"fail_closed_paths"` // paths that use fail-closed mode
	Timeout         time.Duration `yaml:"timeout"`           // classification timeout (default: 10s)
}

type NIMConfig struct {
	APIKey  string        `yaml:"api_key"`
	Model   string        `yaml:"model"`
	BaseURL string        `yaml:"base_url"`
	Timeout time.Duration `yaml:"timeout"`
}

type OllamaConfig struct {
	URL     string        `yaml:"url"`
	Model   string        `yaml:"model"`
	Timeout time.Duration `yaml:"timeout"`
}

type OpenRouterConfig struct {
	APIKey  string        `yaml:"api_key"`
	Model   string        `yaml:"model"`
	BaseURL string        `yaml:"base_url"`
	Timeout time.Duration `yaml:"timeout"`
}

type FailoverConfig struct {
	Threshold float64       `yaml:"threshold"`
	Window    time.Duration `yaml:"window"`
}

type RateLimitConfig struct {
	Default string `yaml:"default"`
}

type RedisConfig struct {
	URL       string         `yaml:"url"`
	Sentinel  SentinelConfig `yaml:"sentinel"`
}

type SentinelConfig struct {
	Enabled    bool     `yaml:"enabled"`
	Addrs      []string `yaml:"addrs"`
	MasterName string   `yaml:"master_name"`
	Password   string   `yaml:"password"`
}

type DatabaseConfig struct {
	URL string `yaml:"url"`
}

type LoggingConfig struct {
	BatchSize        int           `yaml:"batch_size"`
	FlushInterval    time.Duration `yaml:"flush_interval"`
	BufferSize       int           `yaml:"buffer_size"`
	RetentionDays    int           `yaml:"retention_days"`
	RetentionEnabled bool          `yaml:"retention_enabled"`
}

type TLSConfig struct {
	Enabled    bool     `yaml:"enabled"`
	Domains    []string `yaml:"domains"`
	Email      string   `yaml:"email"`
	CacheDir   string   `yaml:"cache_dir"`
	HTTPListen string   `yaml:"http_listen"`
}

type GeoIPConfig struct {
	Enabled bool     `yaml:"enabled"`
	DBPath  string   `yaml:"db_path"`
	Blocked []string `yaml:"blocked"`
	Allowed []string `yaml:"allowed"`
}

type SIEMConfig struct {
	Enabled     bool   `yaml:"enabled"`
	Type        string `yaml:"type"` // syslog, file
	SyslogAddr  string `yaml:"syslog_addr"`
	FilePath    string `yaml:"file_path"`
	Format      string `yaml:"format"` // json, cef
	MinSeverity string `yaml:"min_severity"`
}

type DDoSConfig struct {
	MaxConcurrentConns   int `yaml:"max_concurrent_conns"`
	MaxConnsPerIP        int `yaml:"max_conns_per_ip"`
	MaxNewConnsPerSecond int `yaml:"max_new_conns_per_second"`
	MaxReqsPerConn       int `yaml:"max_reqs_per_conn"`
}

type HoneypotConfig struct {
	Enabled bool     `yaml:"enabled"`
	Paths   []string `yaml:"paths"`
}

type AllowlistConfig struct {
	Enabled bool `yaml:"enabled"`
}

type SessionConfig struct {
	Enabled    bool          `yaml:"enabled"`
	CookieName string        `yaml:"cookie_name"`
	TTL        time.Duration `yaml:"ttl"`
}

type RulesConfig struct {
	ParanoiaLevel    int `yaml:"paranoia_level"`    // 1-4, default 1
	AnomalyThreshold int `yaml:"anomaly_threshold"` // score threshold to block, default 10
}

type ResponseInspectConfig struct {
	Enabled     bool `yaml:"enabled"`
	BlockOnLeak bool `yaml:"block_on_leak"` // block responses that leak sensitive data
}

type BodyInspectConfig struct {
	Enabled          bool `yaml:"enabled"`
	InspectJSON      bool `yaml:"inspect_json"`
	InspectForm      bool `yaml:"inspect_form"`
	InspectMultipart bool `yaml:"inspect_multipart"`
	InspectXML       bool `yaml:"inspect_xml"`
	InspectText      bool `yaml:"inspect_text"`
}

type BruteForceConfig struct {
	Enabled        bool          `yaml:"enabled"`
	MaxAttempts    int           `yaml:"max_attempts"`
	LockDuration   time.Duration `yaml:"lock_duration"`
	WindowDuration time.Duration `yaml:"window_duration"`
}

type ReputationConfig struct {
	Enabled            bool   `yaml:"enabled"`
	AbuseIPDBAPIKey    string `yaml:"abuseipdb_api_key"`
	AutoBlockThreshold int    `yaml:"auto_block_threshold"` // abuse confidence score 0-100
}

type GraphQLConfig struct {
	Enabled            bool     `yaml:"enabled"`
	MaxDepth           int      `yaml:"max_depth"`
	BlockIntrospection bool     `yaml:"block_introspection"`
	MaxComplexity      int      `yaml:"max_complexity"`
	AllowedOperations  []string `yaml:"allowed_operations"`
}

type ATOConfig struct {
	Enabled           bool          `yaml:"enabled"`
	LoginPaths        []string      `yaml:"login_paths"`
	MaxAttemptsPerIP  int           `yaml:"max_attempts_per_ip"`
	MaxUsernamesPerIP int           `yaml:"max_usernames_per_ip"`
	MaxIPsPerUsername int           `yaml:"max_ips_per_username"`
	LockoutDuration   time.Duration `yaml:"lockout_duration"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	if bytes.Contains(data, []byte("!!")) || bytes.Contains(data, []byte("!<")) {
		return nil, fmt.Errorf("parse config: unsafe YAML tags are not allowed in config file")
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if cfg.Server.Listen == "" {
		cfg.Server.Listen = ":8080"
	}
	if cfg.AI.NIM.Timeout == 0 {
		cfg.AI.NIM.Timeout = 2 * time.Second
	}
	if cfg.AI.Ollama.Timeout == 0 {
		cfg.AI.Ollama.Timeout = 5 * time.Second
	}
	if cfg.AI.OpenRouter.Timeout == 0 {
		cfg.AI.OpenRouter.Timeout = 30 * time.Second
	}
	if cfg.AI.Failover.Threshold == 0 {
		cfg.AI.Failover.Threshold = 0.9
	}
	if cfg.AI.Failover.Window == 0 {
		cfg.AI.Failover.Window = 5 * time.Minute
	}
	if cfg.AI.Classify.Timeout == 0 {
		cfg.AI.Classify.Timeout = 10 * time.Second
	}
	if len(cfg.AI.Classify.FailClosedPaths) == 0 {
		cfg.AI.Classify.FailClosedPaths = []string{"/api/v1/auth/", "/admin", "/wp-admin", "/phpmyadmin"}
	}
	if cfg.Logging.BatchSize == 0 {
		cfg.Logging.BatchSize = 100
	}
	if cfg.Logging.FlushInterval == 0 {
		cfg.Logging.FlushInterval = 1 * time.Second
	}
	if cfg.TLS.CacheDir == "" {
		cfg.TLS.CacheDir = "/var/lib/aegis/certs"
	}
	if cfg.TLS.HTTPListen == "" {
		cfg.TLS.HTTPListen = ":80"
	}
	if cfg.GeoIP.DBPath == "" {
		cfg.GeoIP.DBPath = "/var/lib/aegis/GeoLite2-Country.mmdb"
	}
	if cfg.SIEM.Format == "" {
		cfg.SIEM.Format = "json"
	}
	if cfg.SIEM.MinSeverity == "" {
		cfg.SIEM.MinSeverity = "medium"
	}
	if cfg.DDoS.MaxConcurrentConns == 0 {
		cfg.DDoS.MaxConcurrentConns = 1000
	}
	if cfg.DDoS.MaxConnsPerIP == 0 {
		cfg.DDoS.MaxConnsPerIP = 50
	}
	if cfg.DDoS.MaxNewConnsPerSecond == 0 {
		cfg.DDoS.MaxNewConnsPerSecond = 100
	}
	if cfg.DDoS.MaxReqsPerConn == 0 {
		cfg.DDoS.MaxReqsPerConn = 1000
	}
	if cfg.Honeypot.Paths == nil {
		cfg.Honeypot.Paths = []string{"/admin", "/wp-login.php", "/.env", "/phpmyadmin", "/xmlrpc.php"}
	}
	if cfg.Session.CookieName == "" {
		cfg.Session.CookieName = "aegis_session"
	}
	if cfg.Session.TTL == 0 {
		cfg.Session.TTL = 24 * time.Hour
	}
	if cfg.Rules.ParanoiaLevel == 0 {
		cfg.Rules.ParanoiaLevel = 1
	}
	if cfg.Rules.AnomalyThreshold == 0 {
		cfg.Rules.AnomalyThreshold = 10
	}
	if cfg.BruteForce.MaxAttempts == 0 {
		cfg.BruteForce.MaxAttempts = 5
	}
	if cfg.BruteForce.LockDuration == 0 {
		cfg.BruteForce.LockDuration = 15 * time.Minute
	}
	if cfg.BruteForce.WindowDuration == 0 {
		cfg.BruteForce.WindowDuration = 5 * time.Minute
	}
	if cfg.Reputation.AutoBlockThreshold == 0 {
		cfg.Reputation.AutoBlockThreshold = 80
	}
	if len(cfg.ATO.LoginPaths) == 0 {
		cfg.ATO.LoginPaths = []string{"/api/v1/auth/login"}
	}
	if cfg.ATO.MaxAttemptsPerIP == 0 {
		cfg.ATO.MaxAttemptsPerIP = 5
	}
	if cfg.ATO.MaxUsernamesPerIP == 0 {
		cfg.ATO.MaxUsernamesPerIP = 10
	}
	if cfg.ATO.MaxIPsPerUsername == 0 {
		cfg.ATO.MaxIPsPerUsername = 5
	}
	if cfg.ATO.LockoutDuration == 0 {
		cfg.ATO.LockoutDuration = 15 * time.Minute
	}
	if cfg.GraphQL.MaxDepth == 0 {
		cfg.GraphQL.MaxDepth = 10
	}
	if cfg.GraphQL.MaxComplexity == 0 {
		cfg.GraphQL.MaxComplexity = 1000
	}
	// BlockIntrospection: do NOT force-override. Operators who explicitly
	// set block_introspection: false in YAML must be respected. The
	// previous behavior silently overwrote their setting, making it
	// impossible to allow introspection (e.g. for dev tooling). Default
	// behavior: false (zero value) unless operator opts in via YAML.
	if cfg.LibInjection.Threshold == 0 {
		cfg.LibInjection.Threshold = 2
	}

	// Body inspection defaults: all content types enabled when feature is on
	if cfg.BodyInspect.Enabled {
		if !cfg.BodyInspect.InspectJSON && !cfg.BodyInspect.InspectForm &&
			!cfg.BodyInspect.InspectMultipart && !cfg.BodyInspect.InspectXML &&
			!cfg.BodyInspect.InspectText {
			cfg.BodyInspect.InspectJSON = true
			cfg.BodyInspect.InspectForm = true
			cfg.BodyInspect.InspectMultipart = true
			cfg.BodyInspect.InspectXML = true
			cfg.BodyInspect.InspectText = true
		}
	}

	if v := os.Getenv("AEGIS_DATABASE_URL"); v != "" {
		cfg.Database.URL = v
	}
	if v := os.Getenv("AEGIS_REDIS_URL"); v != "" {
		cfg.Redis.URL = v
	}
	if v := os.Getenv("AEGIS_UPSTREAM_URL"); v != "" {
		cfg.Upstream.URL = v
	}
	if v := os.Getenv("AEGIS_NIM_API_KEY"); v != "" {
		cfg.AI.NIM.APIKey = v
	}
	if v := os.Getenv("AEGIS_JWT_SECRET"); v != "" {
		cfg.Auth.JWTSecret = v
	}
	if v := os.Getenv("AEGIS_CORS_ORIGINS"); v != "" {
		cfg.Server.CORSOrigins = strings.Split(v, ",")
	}
	if v := os.Getenv("AEGIS_ABUSEIPDB_API_KEY"); v != "" {
		cfg.Reputation.AbuseIPDBAPIKey = v
	}
	if v := os.Getenv("AEGIS_NIM_API_KEY"); v != "" {
		cfg.AI.NIM.APIKey = v
	}
	if v := os.Getenv("AEGIS_NIM_BASE_URL"); v != "" {
		cfg.AI.NIM.BaseURL = v
	}
	if v := os.Getenv("AEGIS_OPENROUTER_API_KEY"); v != "" {
		cfg.AI.OpenRouter.APIKey = v
	}
	if v := os.Getenv("AEGIS_OPENROUTER_BASE_URL"); v != "" {
		cfg.AI.OpenRouter.BaseURL = v
	}
	if v := os.Getenv("AEGIS_OPENROUTER_MODEL"); v != "" {
		cfg.AI.OpenRouter.Model = v
	}
	if v := os.Getenv("AEGIS_OLLAMA_URL"); v != "" {
		cfg.AI.Ollama.URL = v
	}
	if v := os.Getenv("AEGIS_OLLAMA_MODEL"); v != "" {
		cfg.AI.Ollama.Model = v
	}
	// Set defaults for new protection features
	if cfg.BehavioralBot.ScoreThreshold == 0 {
		cfg.BehavioralBot.ScoreThreshold = 5
	}
	if cfg.BOLA.AnomalyThreshold == 0 {
		cfg.BOLA.AnomalyThreshold = 0.3
	}
	if cfg.CredentialStuffing.MinIPs == 0 {
		cfg.CredentialStuffing.MinIPs = 5
	}
	if cfg.CredentialStuffing.MinAttempts == 0 {
		cfg.CredentialStuffing.MinAttempts = 20
	}
	if cfg.CredentialStuffing.Window == 0 {
		cfg.CredentialStuffing.Window = 10 * time.Minute
	}
	if cfg.SlowDoS.Window1m == 0 {
		cfg.SlowDoS.Window1m = 120
	}
	if cfg.SlowDoS.Window5m == 0 {
		cfg.SlowDoS.Window5m = 500
	}
	if cfg.SlowDoS.Window15m == 0 {
		cfg.SlowDoS.Window15m = 1500
	}
	if cfg.SlowDoS.Action == "" {
		cfg.SlowDoS.Action = "challenge"
	}
	if cfg.ShadowAPI.MinReqCount == 0 {
		cfg.ShadowAPI.MinReqCount = 10
	}
	// P-FREE-1: default-on free community blocklist (CrowdSec + FireHOL).
	if !cfg.ThreatFeed.Enabled && !envBool("AEGIS_THREATFEED_DISABLED") {
		cfg.ThreatFeed.Enabled = true
	}
	// P-FREE-3: default-on WebSocket guard with safe limits.
	if !cfg.WSGuard.Enabled && !envBool("AEGIS_WSGUARD_DISABLED") {
		cfg.WSGuard.Enabled = true
	}
	if cfg.WSGuard.MaxMessageBytes == 0 {
		cfg.WSGuard.MaxMessageBytes = 64 * 1024
	}
	if cfg.WSGuard.HandshakeTimeoutMs == 0 {
		cfg.WSGuard.HandshakeTimeoutMs = 10000
	}
	if cfg.WSGuard.MaxMessagesPerMin == 0 {
		cfg.WSGuard.MaxMessagesPerMin = 600
	}
	if cfg.WSGuard.MaxConnectionsPerIP == 0 {
		cfg.WSGuard.MaxConnectionsPerIP = 5
	}
	// P-FREE-2: default-on CRS auto-update from GitHub.
	if !cfg.CRSUpdate.Enabled && !envBool("AEGIS_CRS_UPDATE_DISABLED") {
		cfg.CRSUpdate.Enabled = true
	}
	if cfg.CRSUpdate.Interval == 0 {
		cfg.CRSUpdate.Interval = 24 * time.Hour
	}
	if cfg.CRSUpdate.GitHubRef == "" {
		cfg.CRSUpdate.GitHubRef = "main"
	}
	// P-FREE-4: default-on free statistical anomaly scoring.
	if !cfg.AnomalyStats.Enabled && !envBool("AEGIS_ANOMALY_DISABLED") {
		cfg.AnomalyStats.Enabled = true
	}
	if cfg.AnomalyStats.EntropyThreshold == 0 {
		cfg.AnomalyStats.EntropyThreshold = 4.5
	}
	if cfg.AnomalyStats.RequestRateZScore == 0 {
		cfg.AnomalyStats.RequestRateZScore = 4.0
	}
	// JWT secret must be explicitly set — no insecure default
	if cfg.BotDetect.Mode == "" {
		cfg.BotDetect.Mode = "log"
	}
	if cfg.Alerts.MinSeverity == "" {
		cfg.Alerts.MinSeverity = "medium"
	}

	return cfg, nil
}

// commonJWTSecrets lists well-known weak defaults that operators frequently
// leave in test / dev configs. Any JWT secret that matches one of these is
// refused at startup.
//
// P-FIX (CRIT-4): reject the obvious "looks like a secret but isn't" values
// (change_me, password, secret, 123456, etc.) so a copy-paste from example
// configs cannot go unnoticed. Combined with the Shannon entropy check
// below, operators are forced to set a meaningful secret.
var commonJWTSecrets = map[string]bool{
	"":                          true,
	"change-me-in-production":   true,
	"change_me":                 true,
	"changeme":                  true,
	"password":                  true,
	"secret":                    true,
	"123456":                    true,
	"123456789":                 true,
	"qwerty":                    true,
	"admin":                     true,
	"letmein":                   true,
	"default":                   true,
	"example":                   true,
	"replace-me":                true,
	"insert-secret-here":        true,
	"${JWT_SECRET}":             true,
	"$JWT_SECRET":               true,
	"todo-set-via-env":          true,
	"supersecret":               true,
	"mysecret":                  true,
	"please-change-me":          true,
}

// minimumSecretEntropy is the minimum Shannon entropy (bits/character)
// required for the JWT secret. 3.5 bits/char is a conservative threshold
// that rejects dictionary words and trivial patterns but allows base64 /
// hex generated secrets.
const minimumSecretEntropy = 3.5

// shannonEntropy returns the Shannon entropy (bits per symbol) of s, using
// byte-wise symbol frequency. Longer strings with more diverse bytes score
// higher. Used by Validate to reject weak JWT secrets.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[byte]int, 256)
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	total := float64(len(s))
	var h float64
	for _, c := range freq {
		p := float64(c) / total
		if p > 0 {
			h -= p * log2(p)
		}
	}
	return h
}

func log2(x float64) float64 {
	const ln2 = 0.6931471805599453
	if x <= 0 {
		return 0
	}
	return _log2(x, ln2)
}

// _log2 = log_2(x). Wraps math.Log from stdlib.
func _log2(x, ln2 float64) float64 { return math.Log(x) / ln2 }

// envBool returns true if the env var is "1", "true", or "yes" (case-insensitive).
// Used to opt OUT of features that default to enabled.
func envBool(name string) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	return v == "1" || v == "true" || v == "yes"
}

func (c *Config) Validate() error {
	if c.Upstream.URL == "" {
		return fmt.Errorf("upstream.url is required")
	}
	if c.Database.URL == "" {
		return fmt.Errorf("database.url is required")
	}
	if c.Redis.URL == "" {
		return fmt.Errorf("redis.url is required")
	}
	// P-FIX (CRIT-4): layered JWT secret validation. We refuse to start if:
	//   1. the secret matches a well-known weak default,
	//   2. the secret still contains a ${...} placeholder, OR
	//   3. the secret is shorter than 32 characters, OR
	//   4. the Shannon entropy is below 3.5 bits/char (i.e. it is
	//      effectively a dictionary word or a trivial pattern).
	if commonJWTSecrets[c.Auth.JWTSecret] {
		return fmt.Errorf("auth.jwt_secret must be set to a secure value; refuse to start with default or weak password")
	}
	if strings.Contains(c.Auth.JWTSecret, "${") {
		return fmt.Errorf("auth.jwt_secret must be set to a secure value; refuse to start with unresolved secret placeholder")
	}
	if len(c.Auth.JWTSecret) < 32 {
		return fmt.Errorf("jwt_secret must be at least 32 characters")
	}
	if e := shannonEntropy(c.Auth.JWTSecret); e < minimumSecretEntropy {
		return fmt.Errorf("jwt_secret has insufficient entropy (%.2f bits/char, minimum %.2f); generate with `openssl rand -base64 48`", e, minimumSecretEntropy)
	}
	return nil
}
