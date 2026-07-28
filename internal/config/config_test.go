package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadValidConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	content := `
server:
  listen: ":9090"
upstream:
  url: "http://localhost:4000"
ai:
  provider: "nim"
  nim:
    api_key: "test-key"
    model: "meta/llama-3.1-8b-instruct"
    base_url: "https://integrate.api.nvidia.com/v1"
    timeout: "3s"
  ollama:
    url: "http://ollama:11434"
    model: "llama3:8b"
    timeout: "5s"
  failover:
    threshold: 0.85
    window: "10m"
rate_limit:
  default: "200/min"
redis:
  url: "redis://localhost:6379"
database:
  url: "postgres://user:pass@localhost:5432/waf?sslmode=disable"
logging:
  batch_size: 50
  flush_interval: "2s"
`
	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.Server.Listen != ":9090" {
		t.Errorf("Listen = %q, want %q", cfg.Server.Listen, ":9090")
	}
	if cfg.Upstream.URL != "http://localhost:4000" {
		t.Errorf("Upstream.URL = %q, want %q", cfg.Upstream.URL, "http://localhost:4000")
	}
	if cfg.AI.NIM.APIKey != "test-key" {
		t.Errorf("NIM APIKey = %q, want %q", cfg.AI.NIM.APIKey, "test-key")
	}
	if cfg.AI.NIM.Timeout != 3*time.Second {
		t.Errorf("NIM Timeout = %v, want %v", cfg.AI.NIM.Timeout, 3*time.Second)
	}
	if cfg.AI.Failover.Threshold != 0.85 {
		t.Errorf("Failover Threshold = %f, want %f", cfg.AI.Failover.Threshold, 0.85)
	}
	if cfg.Logging.BatchSize != 50 {
		t.Errorf("BatchSize = %d, want %d", cfg.Logging.BatchSize, 50)
	}
}

func TestLoadDefaults(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	content := `
upstream:
  url: "http://localhost:3000"
redis:
  url: "redis://localhost:6379"
database:
  url: "postgres://localhost:5432/waf"
`
	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.Server.Listen != ":8080" {
		t.Errorf("default Listen = %q, want %q", cfg.Server.Listen, ":8080")
	}
	if cfg.AI.NIM.Timeout != 2*time.Second {
		t.Errorf("default NIM Timeout = %v, want %v", cfg.AI.NIM.Timeout, 2*time.Second)
	}
	if cfg.AI.Failover.Threshold != 0.9 {
		t.Errorf("default Threshold = %f, want %f", cfg.AI.Failover.Threshold, 0.9)
	}
	if cfg.AI.Ollama.Timeout != 5*time.Second {
		t.Errorf("default Ollama Timeout = %v, want %v", cfg.AI.Ollama.Timeout, 5*time.Second)
	}
	if cfg.AI.Failover.Window != 5*time.Minute {
		t.Errorf("default Failover Window = %v, want %v", cfg.AI.Failover.Window, 5*time.Minute)
	}
	if cfg.Logging.BatchSize != 100 {
		t.Errorf("default BatchSize = %d, want %d", cfg.Logging.BatchSize, 100)
	}
	if cfg.Logging.FlushInterval != 1*time.Second {
		t.Errorf("default FlushInterval = %v, want %v", cfg.Logging.FlushInterval, 1*time.Second)
	}
	if cfg.SlowDoS.Window1m != 120 || cfg.SlowDoS.Window5m != 500 || cfg.SlowDoS.Window15m != 1500 {
		t.Errorf("default SlowDoS windows = %d/%d/%d", cfg.SlowDoS.Window1m, cfg.SlowDoS.Window5m, cfg.SlowDoS.Window15m)
	}
	if cfg.BOLA.AnomalyThreshold != 0.3 {
		t.Errorf("default BOLA AnomalyThreshold = %f", cfg.BOLA.AnomalyThreshold)
	}
	if cfg.CredentialStuffing.MinIPs != 5 || cfg.CredentialStuffing.MinAttempts != 20 || cfg.CredentialStuffing.Window != 10*time.Minute {
		t.Errorf("default credential stuffing config = %+v", cfg.CredentialStuffing)
	}
	if cfg.ShadowAPI.MinReqCount != 10 {
		t.Errorf("default ShadowAPI MinReqCount = %d", cfg.ShadowAPI.MinReqCount)
	}
}

func TestEnvVarOverrides(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	content := `
upstream:
  url: "http://default:3000"
database:
  url: "postgres://default:5432/waf"
redis:
  url: "redis://default:6379"
`
	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("AEGIS_DATABASE_URL", "postgres://override:5432/waf")
	t.Setenv("AEGIS_REDIS_URL", "redis://override:6379")
	t.Setenv("AEGIS_UPSTREAM_URL", "http://override:3000")
	t.Setenv("AEGIS_NIM_API_KEY", "override-key")

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.Database.URL != "postgres://override:5432/waf" {
		t.Errorf("Database.URL = %q, want override", cfg.Database.URL)
	}
	if cfg.Redis.URL != "redis://override:6379" {
		t.Errorf("Redis.URL = %q, want override", cfg.Redis.URL)
	}
	if cfg.Upstream.URL != "http://override:3000" {
		t.Errorf("Upstream.URL = %q, want override", cfg.Upstream.URL)
	}
	if cfg.AI.NIM.APIKey != "override-key" {
		t.Errorf("NIM.APIKey = %q, want override", cfg.AI.NIM.APIKey)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{"valid", Config{
			Upstream: UpstreamConfig{URL: "http://app:3000"},
			Database: DatabaseConfig{URL: "postgres://localhost/waf"},
			Redis:    RedisConfig{URL: "redis://localhost:6379"},
			Auth:     AuthConfig{JWTSecret: "test-secret-that-is-at-least-32-characters-long"},
		}, false},
		{"missing upstream", Config{
			Database: DatabaseConfig{URL: "postgres://localhost/waf"},
			Redis:    RedisConfig{URL: "redis://localhost:6379"},
		}, true},
		{"missing database", Config{
			Upstream: UpstreamConfig{URL: "http://app:3000"},
			Redis:    RedisConfig{URL: "redis://localhost:6379"},
		}, true},
		{"missing redis", Config{
			Upstream: UpstreamConfig{URL: "http://app:3000"},
			Database: DatabaseConfig{URL: "postgres://localhost/waf"},
		}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	if err == nil {
		t.Error("expected error for missing file")
	}
}
