# Phase 1: Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Get all infrastructure running: Docker containers (nginx, postgres, redis, ollama), Go project scaffolding with config loading, database schema, Redis connection, basic reverse proxy to configurable upstream, and a health endpoint. After this phase, `docker compose up` starts everything and the WAF proxies real traffic.

**Architecture:** Monolithic Go binary handles reverse proxy + REST API. Nginx fronts it for TLS and static files. Postgres for persistence, Redis for caching/rate-limiting. Config via YAML with env var overrides.

**Tech Stack:** Go 1.22+, PostgreSQL 16, Redis 7, nginx alpine, Docker Compose v2

---

## File Map

```
waf/
├── cmd/waf-engine/main.go              # entrypoint: loads config, connects DB/Redis, starts server
├── internal/
│   ├── config/config.go                 # Config struct, YAML loading, env var overrides
│   ├── config/config_test.go            # config loading tests
│   ├── db/postgres.go                   # Postgres connection pool + migration runner
│   ├── db/postgres_test.go              # connection test
│   ├── db/redis.go                      # Redis client setup
│   ├── db/redis_test.go                 # Redis ping test
│   ├── api/router.go                    # chi router, mounts all routes
│   ├── api/response.go                  # JSON response helpers (Success, Error)
│   ├── api/response_test.go             # response helper tests
│   ├── api/health.go                    # GET /api/v1/health handler
│   ├── api/health_test.go              # health endpoint test
│   ├── proxy/proxy.go                   # reverse proxy handler
│   └── proxy/proxy_test.go             # proxy test (httptest upstream)
├── migrations/
│   └── 001_initial_schema.sql           # all tables + indexes
├── docker/
│   ├── nginx/nginx.conf                 # nginx config: TLS, static files, proxy to waf-engine
│   └── waf-engine/Dockerfile            # multi-stage Go build
├── docker-compose.yml                   # all containers
├── config.yaml                          # default config
├── go.mod
└── go.sum
```

---

### Task 1: Docker Compose + Nginx + Config

**Files:**
- Create: `docker-compose.yml`
- Create: `docker/nginx/nginx.conf`
- Create: `config.yaml`

- [ ] **Step 1: Create config.yaml**

```yaml
# /home/ubuntu/waf/config.yaml
server:
  listen: ":8080"
upstream:
  url: "http://host.docker.internal:3000"
ai:
  provider: "nim"
  nim:
    api_key: ""
    model: "meta/llama-3.1-8b-instruct"
    base_url: "https://integrate.api.nvidia.com/v1"
    timeout: "2s"
  ollama:
    url: "http://ollama:11434"
    model: "llama3:8b"
    timeout: "5s"
  failover:
    threshold: 0.9
    window: "5m"
rate_limit:
  default: "100/min"
redis:
  url: "redis://redis:6379"
database:
  url: "postgres://waf:wafpassword@postgres:5432/waf?sslmode=disable"
logging:
  batch_size: 100
  flush_interval: "1s"
```

- [ ] **Step 2: Create nginx.conf**

```nginx
# /home/ubuntu/waf/docker/nginx/nginx.conf
events {
    worker_connections 1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent"';

    access_log /var/log/nginx/access.log main;
    error_log  /var/log/nginx/error.log warn;

    sendfile on;
    keepalive_timeout 65;

    # Rate limiting at nginx level
    limit_req_zone $binary_remote_addr zone=api:10m rate=30r/s;

    server {
        listen 80;
        server_name _;

        # Dashboard static files
        location / {
            root /usr/share/nginx/html;
            index index.html;
            try_files $uri $uri/ /index.html;
        }

        # API and proxy — forward to Go backend
        location /api/ {
            limit_req zone=api burst=50 nodelay;
            proxy_pass http://waf-engine:8080;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;

            # WebSocket support
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_read_timeout 86400;
        }

        # Health check
        location /health {
            proxy_pass http://waf-engine:8080/api/v1/health;
        }
    }
}
```

- [ ] **Step 3: Create docker-compose.yml**

```yaml
# /home/ubuntu/waf/docker-compose.yml
version: "3.8"

services:
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./docker/nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./dashboard/dist:/usr/share/nginx/html:ro
    depends_on:
      - waf-engine
    restart: unless-stopped

  waf-engine:
    build:
      context: .
      dockerfile: docker/waf-engine/Dockerfile
    ports:
      - "8080:8080"
    environment:
      - WAF_DATABASE_URL=postgres://waf:wafpassword@postgres:5432/waf?sslmode=disable
      - WAF_REDIS_URL=redis://redis:6379
      - WAF_UPSTREAM_URL=http://host.docker.internal:3000
      - WAF_NIM_API_KEY=${NIM_API_KEY:-}
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    extra_hosts:
      - "host.docker.internal:host-gateway"
    restart: unless-stopped

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: waf
      POSTGRES_USER: waf
      POSTGRES_PASSWORD: wafpassword
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data
      - ./migrations:/docker-entrypoint-initdb.d:ro
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U waf -d waf"]
      interval: 5s
      timeout: 5s
      retries: 5
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redisdata:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 5s
      retries: 5
    restart: unless-stopped

  ollama:
    image: ollama/ollama:latest
    ports:
      - "11434:11434"
    volumes:
      - ollamadata:/root/.ollama
    restart: unless-stopped

volumes:
  pgdata:
  redisdata:
  ollamadata:
```

- [ ] **Step 4: Verify docker-compose syntax**

Run: `docker compose config`
Expected: Valid YAML output with all 5 services listed.

- [ ] **Step 5: Commit**

```bash
git add docker-compose.yml docker/nginx/nginx.conf config.yaml
git commit -m "feat: add Docker Compose, nginx config, default config.yaml"
```

---

### Task 2: Go Module + Config Loading

**Files:**
- Create: `go.mod`
- Create: `internal/config/config.go`
- Create: `internal/config/config_test.go`

- [ ] **Step 1: Initialize Go module**

Run:
```bash
cd /home/ubuntu/waf
go mod init github.com/user/waf
```

Expected: `go.mod` created.

- [ ] **Step 2: Create config.go**

```go
// /home/ubuntu/waf/internal/config/config.go
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server    ServerConfig    `yaml:"server"`
	Upstream  UpstreamConfig  `yaml:"upstream"`
	AI        AIConfig        `yaml:"ai"`
	RateLimit RateLimitConfig `yaml:"rate_limit"`
	Redis     RedisConfig     `yaml:"redis"`
	Database  DatabaseConfig  `yaml:"database"`
	Logging   LoggingConfig   `yaml:"logging"`
}

type ServerConfig struct {
	Listen string `yaml:"listen"`
}

type UpstreamConfig struct {
	URL string `yaml:"url"`
}

type AIConfig struct {
	Provider string       `yaml:"provider"`
	NIM      NIMConfig    `yaml:"nim"`
	Ollama   OllamaConfig `yaml:"ollama"`
	Failover FailoverConfig `yaml:"failover"`
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

type FailoverConfig struct {
	Threshold float64       `yaml:"threshold"`
	Window    time.Duration `yaml:"window"`
}

type RateLimitConfig struct {
	Default string `yaml:"default"`
}

type RedisConfig struct {
	URL string `yaml:"url"`
}

type DatabaseConfig struct {
	URL string `yaml:"url"`
}

type LoggingConfig struct {
	BatchSize     int           `yaml:"batch_size"`
	FlushInterval time.Duration `yaml:"flush_interval"`
}

// Load reads config from YAML file, then applies environment variable overrides.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	// Expand environment variables in YAML (${VAR} syntax)
	expanded := os.ExpandEnv(string(data))

	cfg := &Config{}
	if err := yaml.Unmarshal([]byte(expanded), cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	// Set defaults
	if cfg.Server.Listen == "" {
		cfg.Server.Listen = ":8080"
	}
	if cfg.AI.NIM.Timeout == 0 {
		cfg.AI.NIM.Timeout = 2 * time.Second
	}
	if cfg.AI.Ollama.Timeout == 0 {
		cfg.AI.Ollama.Timeout = 5 * time.Second
	}
	if cfg.AI.Failover.Threshold == 0 {
		cfg.AI.Failover.Threshold = 0.9
	}
	if cfg.AI.Failover.Window == 0 {
		cfg.AI.Failover.Window = 5 * time.Minute
	}
	if cfg.Logging.BatchSize == 0 {
		cfg.Logging.BatchSize = 100
	}
	if cfg.Logging.FlushInterval == 0 {
		cfg.Logging.FlushInterval = 1 * time.Second
	}

	// Environment variable overrides
	if v := os.Getenv("WAF_DATABASE_URL"); v != "" {
		cfg.Database.URL = v
	}
	if v := os.Getenv("WAF_REDIS_URL"); v != "" {
		cfg.Redis.URL = v
	}
	if v := os.Getenv("WAF_UPSTREAM_URL"); v != "" {
		cfg.Upstream.URL = v
	}
	if v := os.Getenv("WAF_NIM_API_KEY"); v != "" {
		cfg.AI.NIM.APIKey = v
	}

	return cfg, nil
}

// Validate checks required fields are set.
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
	return nil
}
```

- [ ] **Step 3: Create config_test.go**

```go
// /home/ubuntu/waf/internal/config/config_test.go
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

	os.Setenv("WAF_DATABASE_URL", "postgres://override:5432/waf")
	os.Setenv("WAF_REDIS_URL", "redis://override:6379")
	os.Setenv("WAF_UPSTREAM_URL", "http://override:3000")
	defer func() {
		os.Unsetenv("WAF_DATABASE_URL")
		os.Unsetenv("WAF_REDIS_URL")
		os.Unsetenv("WAF_UPSTREAM_URL")
	}()

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
```

- [ ] **Step 4: Install yaml dependency and run tests**

Run:
```bash
cd /home/ubuntu/waf
go get gopkg.in/yaml.v3
go test ./internal/config/ -v
```

Expected: All 5 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add go.mod go.sum internal/config/
git commit -m "feat: add config loading with YAML + env var overrides"
```

---

### Task 3: Database Connection + Migrations

**Files:**
- Create: `internal/db/postgres.go`
- Create: `internal/db/postgres_test.go`
- Create: `migrations/001_initial_schema.sql`

- [ ] **Step 1: Create migration SQL**

```sql
-- /home/ubuntu/waf/migrations/001_initial_schema.sql

CREATE TABLE IF NOT EXISTS rules (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    pattern TEXT NOT NULL,
    match_type VARCHAR(50) NOT NULL,
    action VARCHAR(20) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    priority INT DEFAULT 100,
    enabled BOOLEAN DEFAULT true,
    hit_count BIGINT DEFAULT 0,
    source VARCHAR(50) DEFAULT 'manual',
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS request_logs (
    id BIGSERIAL,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    client_ip INET NOT NULL,
    method VARCHAR(10) NOT NULL,
    host VARCHAR(255) NOT NULL,
    path TEXT NOT NULL,
    query TEXT,
    headers JSONB,
    body_hash VARCHAR(64),
    user_agent TEXT,
    action VARCHAR(20) NOT NULL,
    rule_id INT REFERENCES rules(id),
    threat_score FLOAT,
    ai_classification VARCHAR(50),
    response_code INT,
    response_time_ms INT,
    country VARCHAR(2),
    asn VARCHAR(50),
    bytes_sent BIGINT,
    bytes_received BIGINT
);

CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON request_logs (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_logs_client_ip ON request_logs (client_ip);
CREATE INDEX IF NOT EXISTS idx_logs_action ON request_logs (action);
CREATE INDEX IF NOT EXISTS idx_logs_threat ON request_logs (threat_score) WHERE threat_score > 0.7;

CREATE TABLE IF NOT EXISTS ai_decisions (
    id BIGSERIAL PRIMARY KEY,
    request_id BIGINT,
    model_name VARCHAR(100) NOT NULL,
    provider VARCHAR(20) NOT NULL,
    threat_score FLOAT NOT NULL,
    classification VARCHAR(50) NOT NULL,
    reasoning TEXT,
    latency_ms INT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS anomalies (
    id SERIAL PRIMARY KEY,
    type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    description TEXT NOT NULL,
    context JSONB,
    resolved BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    resolved_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS blocked_ips (
    id SERIAL PRIMARY KEY,
    ip_cidr CIDR NOT NULL,
    reason TEXT,
    source VARCHAR(50) DEFAULT 'manual',
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_blocked_ips_cidr ON blocked_ips USING GIST (ip_cidr);

CREATE TABLE IF NOT EXISTS ai_rule_suggestions (
    id SERIAL PRIMARY KEY,
    pattern TEXT NOT NULL,
    match_type VARCHAR(50) NOT NULL,
    suggested_action VARCHAR(20) NOT NULL,
    confidence FLOAT NOT NULL,
    sample_attacks JSONB,
    status VARCHAR(20) DEFAULT 'pending',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS config (
    key VARCHAR(255) PRIMARY KEY,
    value JSONB NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules (enabled) WHERE enabled = true;
```

- [ ] **Step 2: Create postgres.go**

```go
// /home/ubuntu/waf/internal/db/postgres.go
package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Postgres struct {
	Pool *pgxpool.Pool
}

func NewPostgres(ctx context.Context, databaseURL string) (*Postgres, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}

	config.MaxConns = 20
	config.MinConns = 2
	config.MaxConnLifetime = 30 * time.Minute
	config.MaxConnIdleTime = 5 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}

	return &Postgres{Pool: pool}, nil
}

func (p *Postgres) Close() {
	p.Pool.Close()
}

func (p *Postgres) Ping(ctx context.Context) error {
	return p.Pool.Ping(ctx)
}
```

- [ ] **Step 3: Create postgres_test.go**

```go
// /home/ubuntu/waf/internal/db/postgres_test.go
package db

import (
	"context"
	"os"
	"testing"
)

func TestPostgresConnection(t *testing.T) {
	dsn := os.Getenv("WAF_TEST_DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://waf:wafpassword@localhost:5432/waf?sslmode=disable"
	}

	ctx := context.Background()
	pg, err := NewPostgres(ctx, dsn)
	if err != nil {
		t.Skipf("Postgres not available: %v", err)
	}
	defer pg.Close()

	if err := pg.Ping(ctx); err != nil {
		t.Fatalf("Ping() error: %v", err)
	}
}
```

- [ ] **Step 4: Install pgx dependency**

Run:
```bash
cd /home/ubuntu/waf
go get github.com/jackc/pgx/v5
go mod tidy
```

- [ ] **Step 5: Start postgres, run migration, run test**

Run:
```bash
docker compose up -d postgres
sleep 5
go test ./internal/db/ -v -run TestPostgresConnection
```

Expected: PASS (or SKIP if postgres not running).

- [ ] **Step 6: Commit**

```bash
git add internal/db/postgres.go internal/db/postgres_test.go migrations/
git commit -m "feat: add Postgres connection pool + initial schema migration"
```

---

### Task 4: Redis Connection

**Files:**
- Create: `internal/db/redis.go`
- Create: `internal/db/redis_test.go`

- [ ] **Step 1: Create redis.go**

```go
// /home/ubuntu/waf/internal/db/redis.go
package db

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
)

type Redis struct {
	Client *redis.Client
}

func NewRedis(ctx context.Context, redisURL string) (*Redis, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("parse redis url: %w", err)
	}

	client := redis.NewClient(opts)

	if err := client.Ping(ctx).Err(); err != nil {
		client.Close()
		return nil, fmt.Errorf("ping redis: %w", err)
	}

	return &Redis{Client: client}, nil
}

func (r *Redis) Close() error {
	return r.Client.Close()
}

func (r *Redis) Ping(ctx context.Context) error {
	return r.Client.Ping(ctx).Err()
}
```

- [ ] **Step 2: Create redis_test.go**

```go
// /home/ubuntu/waf/internal/db/redis_test.go
package db

import (
	"context"
	"os"
	"testing"
)

func TestRedisConnection(t *testing.T) {
	redisURL := os.Getenv("WAF_TEST_REDIS_URL")
	if redisURL == "" {
		redisURL = "redis://localhost:6379"
	}

	ctx := context.Background()
	r, err := NewRedis(ctx, redisURL)
	if err != nil {
		t.Skipf("Redis not available: %v", err)
	}
	defer r.Close()

	if err := r.Ping(ctx); err != nil {
		t.Fatalf("Ping() error: %v", err)
	}
}
```

- [ ] **Step 3: Install redis dependency**

Run:
```bash
cd /home/ubuntu/waf
go get github.com/redis/go-redis/v9
go mod tidy
```

- [ ] **Step 4: Start redis, run test**

Run:
```bash
docker compose up -d redis
sleep 3
go test ./internal/db/ -v -run TestRedisConnection
```

Expected: PASS (or SKIP if redis not running).

- [ ] **Step 5: Commit**

```bash
git add internal/db/redis.go internal/db/redis_test.go go.mod go.sum
git commit -m "feat: add Redis client connection"
```

---

### Task 5: JSON Response Helpers + API Router

**Files:**
- Create: `internal/api/response.go`
- Create: `internal/api/response_test.go`
- Create: `internal/api/router.go`

- [ ] **Step 1: Create response.go**

```go
// /home/ubuntu/waf/internal/api/response.go
package api

import (
	"encoding/json"
	"net/http"
)

type SuccessResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data"`
	Meta    *Meta       `json:"meta,omitempty"`
}

type ErrorResponse struct {
	Success bool        `json:"success"`
	Error   ErrorDetail `json:"error"`
}

type ErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Meta struct {
	Page    int `json:"page"`
	PerPage int `json:"per_page"`
	Total   int `json:"total"`
}

func RespondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(SuccessResponse{
		Success: true,
		Data:    data,
	})
}

func RespondJSONWithMeta(w http.ResponseWriter, status int, data interface{}, meta *Meta) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(SuccessResponse{
		Success: true,
		Data:    data,
		Meta:    meta,
	})
}

func RespondError(w http.ResponseWriter, status int, code string, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ErrorResponse{
		Success: false,
		Error: ErrorDetail{
			Code:    code,
			Message: message,
		},
	})
}
```

- [ ] **Step 2: Create response_test.go**

```go
// /home/ubuntu/waf/internal/api/response_test.go
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRespondJSON(t *testing.T) {
	w := httptest.NewRecorder()
	RespondJSON(w, http.StatusOK, map[string]string{"key": "value"})

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var resp SuccessResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Success {
		t.Error("expected success=true")
	}
}

func TestRespondError(t *testing.T) {
	w := httptest.NewRecorder()
	RespondError(w, http.StatusNotFound, "NOT_FOUND", "resource not found")

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}

	var resp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Success {
		t.Error("expected success=false")
	}
	if resp.Error.Code != "NOT_FOUND" {
		t.Errorf("error code = %q, want NOT_FOUND", resp.Error.Code)
	}
}

func TestRespondJSONWithMeta(t *testing.T) {
	w := httptest.NewRecorder()
	RespondJSONWithMeta(w, http.StatusOK, []int{1, 2, 3}, &Meta{
		Page: 1, PerPage: 50, Total: 100,
	})

	var resp SuccessResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Meta == nil {
		t.Fatal("expected meta to be set")
	}
	if resp.Meta.Total != 100 {
		t.Errorf("meta.Total = %d, want 100", resp.Meta.Total)
	}
}
```

- [ ] **Step 3: Create router.go**

```go
// /home/ubuntu/waf/internal/api/router.go
package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func NewRouter() http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Heartbeat("/ping"))

	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/health", HandleHealth)

		// Placeholder routes — implemented in later phases
		// r.Route("/dashboard", func(r chi.Router) { ... })
		// r.Route("/rules", func(r chi.Router) { ... })
		// r.Route("/blocked-ips", func(r chi.Router) { ... })
		// r.Route("/logs", func(r chi.Router) { ... })
		// r.Route("/ai", func(r chi.Router) { ... })
		// r.Route("/anomalies", func(r chi.Router) { ... })
		// r.Route("/settings", func(r chi.Router) { ... })
	})

	return r
}
```

- [ ] **Step 4: Install chi dependency**

Run:
```bash
cd /home/ubuntu/waf
go get github.com/go-chi/chi/v5
go mod tidy
```

- [ ] **Step 5: Run response tests**

Run: `go test ./internal/api/ -v`
Expected: All 3 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/api/response.go internal/api/response_test.go internal/api/router.go go.mod go.sum
git commit -m "feat: add JSON response helpers and chi router"
```

---

### Task 6: Health Endpoint

**Files:**
- Create: `internal/api/health.go`
- Create: `internal/api/health_test.go`

- [ ] **Step 1: Create health.go**

```go
// /home/ubuntu/waf/internal/api/health.go
package api

import (
	"net/http"
	"runtime"
	"time"
)

var startTime = time.Now()

type HealthResponse struct {
	Status  string `json:"status"`
	Uptime  string `json:"uptime"`
	Version string `json:"version"`
	Go      string `json:"go"`
}

func HandleHealth(w http.ResponseWriter, r *http.Request) {
	RespondJSON(w, http.StatusOK, HealthResponse{
		Status:  "ok",
		Uptime:  time.Since(startTime).Round(time.Second).String(),
		Version: "0.1.0",
		Go:      runtime.Version(),
	})
}
```

- [ ] **Step 2: Create health_test.go**

```go
// /home/ubuntu/waf/internal/api/health_test.go
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleHealth(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	w := httptest.NewRecorder()

	HandleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp SuccessResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if !resp.Success {
		t.Error("expected success=true")
	}
}
```

- [ ] **Step 3: Run tests**

Run: `go test ./internal/api/ -v`
Expected: All tests PASS including health test.

- [ ] **Step 4: Commit**

```bash
git add internal/api/health.go internal/api/health_test.go
git commit -m "feat: add health endpoint"
```

---

### Task 7: Reverse Proxy

**Files:**
- Create: `internal/proxy/proxy.go`
- Create: `internal/proxy/proxy_test.go`

- [ ] **Step 1: Create proxy.go**

```go
// /home/ubuntu/waf/internal/proxy/proxy.go
package proxy

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

type Proxy struct {
	target  *url.URL
	handler *httputil.ReverseProxy
}

func New(upstreamURL string) (*Proxy, error) {
	target, err := url.Parse(upstreamURL)
	if err != nil {
		return nil, err
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("proxy error: %v", err)
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(`{"success":false,"error":{"code":"UPSTREAM_ERROR","message":"upstream unavailable"}}`))
	}

	return &Proxy{
		target:  target,
		handler: proxy,
	}, nil
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Host = p.target.Host
	p.handler.ServeHTTP(w, r)
}
```

- [ ] **Step 2: Create proxy_test.go**

```go
// /home/ubuntu/waf/internal/proxy/proxy_test.go
package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProxyForwardsRequest(t *testing.T) {
	// Start a fake upstream
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream", "true")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"upstream-ok"}`))
	}))
	defer upstream.Close()

	p, err := New(upstream.URL)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// Create a request through the proxy
	req := httptest.NewRequest("GET", "/test?foo=bar", nil)
	req.Header.Set("X-Custom", "value")
	w := httptest.NewRecorder()

	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	if w.Header().Get("X-Upstream") != "true" {
		t.Error("expected X-Upstream header from upstream")
	}

	body, _ := io.ReadAll(w.Body)
	if string(body) != `{"status":"upstream-ok"}` {
		t.Errorf("body = %q, want upstream response", string(body))
	}
}

func TestProxyUpstreamDown(t *testing.T) {
	p, err := New("http://localhost:19999") // nothing listening
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	p.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadGateway)
	}
}

func TestProxyInvalidURL(t *testing.T) {
	_, err := New("://invalid")
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}
```

- [ ] **Step 3: Run proxy tests**

Run: `go test ./internal/proxy/ -v`
Expected: All 3 tests PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/proxy/
git commit -m "feat: add reverse proxy with error handling"
```

---

### Task 8: main.go — Wire Everything Together

**Files:**
- Create: `cmd/waf-engine/main.go`
- Create: `docker/waf-engine/Dockerfile`

- [ ] **Step 1: Create main.go**

```go
// /home/ubuntu/waf/cmd/waf-engine/main.go
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/user/waf/internal/api"
	"github.com/user/waf/internal/config"
	"github.com/user/waf/internal/db"
	"github.com/user/waf/internal/proxy"
)

func main() {
	// Load config
	cfgPath := os.Getenv("WAF_CONFIG")
	if cfgPath == "" {
		cfgPath = "config.yaml"
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	if err := cfg.Validate(); err != nil {
		log.Fatalf("invalid config: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Connect to Postgres
	pg, err := db.NewPostgres(ctx, cfg.Database.URL)
	if err != nil {
		log.Fatalf("connect postgres: %v", err)
	}
	defer pg.Close()
	log.Println("connected to postgres")

	// Connect to Redis
	rdb, err := db.NewRedis(ctx, cfg.Redis.URL)
	if err != nil {
		log.Fatalf("connect redis: %v", err)
	}
	defer rdb.Close()
	log.Println("connected to redis")

	// Create reverse proxy
	proxyHandler, err := proxy.New(cfg.Upstream.URL)
	if err != nil {
		log.Fatalf("create proxy: %v", err)
	}
	log.Printf("proxying to %s", cfg.Upstream.URL)

	// Create API router
	router := api.NewRouter()

	// Combine: API routes + catch-all proxy
	mux := http.NewServeMux()
	mux.Handle("/api/", router)
	mux.Handle("/", proxyHandler)

	server := &http.Server{
		Addr:         cfg.Server.Listen,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("shutting down...")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		server.Shutdown(shutdownCtx)
	}()

	log.Printf("waf-engine listening on %s", cfg.Server.Listen)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
	log.Println("server stopped")
}
```

- [ ] **Step 2: Verify it compiles**

Run:
```bash
cd /home/ubuntu/waf
go build ./cmd/waf-engine/
```

Expected: Binary `waf` created in current directory, no errors.

- [ ] **Step 3: Run all unit tests**

Run:
```bash
go test ./internal/... -v -short
```

Expected: All tests PASS (DB/Redis tests SKIP if services not running).

- [ ] **Step 4: Create Dockerfile**

```dockerfile
# /home/ubuntu/waf/docker/waf-engine/Dockerfile
FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /waf-engine ./cmd/waf-engine/

FROM alpine:3.19

RUN apk --no-cache add ca-certificates tzdata
COPY --from=builder /waf-engine /usr/local/bin/waf-engine
COPY config.yaml /etc/waf/config.yaml

EXPOSE 8080

ENTRYPOINT ["waf-engine"]
```

- [ ] **Step 5: Commit**

```bash
git add cmd/waf-engine/main.go docker/waf-engine/Dockerfile
git commit -m "feat: add main.go entrypoint + Dockerfile"
```

---

### Task 9: End-to-End Verification

- [ ] **Step 1: Start all containers**

Run:
```bash
cd /home/ubuntu/waf
docker compose up -d --build
```

Expected: All containers start. `docker compose ps` shows all healthy.

- [ ] **Step 2: Check logs**

Run:
```bash
docker compose logs waf-engine --tail 20
```

Expected: "connected to postgres", "connected to redis", "waf-engine listening on :8080".

- [ ] **Step 3: Test health endpoint**

Run:
```bash
curl -s http://localhost/api/v1/health | jq .
```

Expected:
```json
{
  "success": true,
  "data": {
    "status": "ok",
    "uptime": "...",
    "version": "0.1.0",
    "go": "go1.22.x"
  }
}
```

- [ ] **Step 4: Test proxy (requires upstream)**

If you have a real app running on port 3000:
```bash
curl -s http://localhost/your-endpoint
```

Expected: Response from upstream app proxied through WAF.

If no upstream: proxy returns 502 (expected behavior — WAF is working, upstream is down).

- [ ] **Step 5: Verify database tables exist**

Run:
```bash
docker compose exec postgres psql -U waf -d waf -c "\dt"
```

Expected: All 7 tables listed (rules, request_logs, ai_decisions, anomalies, blocked_ips, ai_rule_suggestions, config).

- [ ] **Step 6: Verify Redis**

Run:
```bash
docker compose exec redis redis-cli ping
```

Expected: `PONG`

- [ ] **Step 7: Commit final state**

```bash
git add -A
git commit -m "chore: phase 1 complete — foundation verified"
```

---

## Phase 1 Success Criteria

- [ ] `docker compose up -d --build` starts all containers
- [ ] `GET /api/v1/health` returns `{"success": true, "data": {"status": "ok"}}`
- [ ] Proxy forwards requests to upstream (502 if no upstream)
- [ ] All 7 Postgres tables exist with correct schema
- [ ] Redis responds to PING
- [ ] All unit tests pass: `go test ./internal/... -v -short`
- [ ] No crashes in logs after 60 seconds of uptime
