# Advanced AI-Powered Web Application Firewall — Design Spec

**Date:** 2026-05-24
**Status:** Approved by user

## Overview

Production-grade Web Application Firewall with AI-powered threat detection, real-time dashboard, and single-server Docker deployment. All free/open-source tooling. No auth (added later). All dashboard data from real traffic — no mock data, no demo mode.

---

## Section 1: System Architecture

### Approach

Monolithic Go engine (Approach A). Single binary handles reverse proxy, middleware pipeline, AI integration, REST API, WebSocket server. Chosen for: simplest deployment, single process to debug, no inter-service latency on proxy path, lowest resource usage.

### Docker Containers (7)

| Container | Image | Port | Purpose |
|-----------|-------|------|---------|
| `nginx` | nginx:alpine | :443, :80 | TLS termination, static files, reverse proxy to Go |
| `waf-engine` | custom Go | :8080 (internal) | Proxy + middleware + AI + API + WebSocket |
| `postgres` | postgres:16 | :5432 (internal) | Persistent storage |
| `redis` | redis:7-alpine | :6379 (internal) | Caching, rate limiting, real-time counters |
| `ollama` | ollama/ollama | :11434 (internal) | Local LLM fallback |
| NIM | cloud API | — | No container. API calls to integrate.api.nvidia.com |
| `dashboard` | built by nginx | — | React SPA served by nginx |

### Request Flow

```
Client → Nginx (:443) → WAF Engine (:8080)
  → IP Reputation Check
  → Rate Limiter
  → Static Rule Engine
  → AI Classifier (NIM primary → Ollama fallback)
  → Request Logger (async Postgres + WebSocket push)
  → Proxy to Upstream App
```

### AI Routing

- **Primary:** NVIDIA NIM (cloud, free tier, meta/llama-3.1-8b-instruct)
- **Fallback:** Ollama (local, llama3:8b)
- **Failover:** NIM success rate < 90% over 5-minute window → switch to Ollama. Auto-recover when NIM > 90%.
- **Fail-open:** If both down, allow request + log error.

### Config

`config.yaml` at project root — upstream URL, NIM API key, Ollama URL, rate limits, AI thresholds, log retention. Environment variables override YAML values.

---

## Section 2: Go WAF Engine Internals

### Middleware Pipeline (ordered, per-request)

1. **IP Reputation Check** — `blocked_ips` table cached in Redis. CIDR range matching via `net.IP`. GeoIP optional (MaxMind free GeoLite2).
2. **Rate Limiter** — token bucket via Redis. Per-IP and per-endpoint configurable. Atomic Lua script for increment.
3. **Static Rule Engine** — regex/pattern matching. OWASP CRS-style rules. Priority-ordered. Stop on first match. Actions: block, allow, log-only.
4. **AI Classifier** — if static rules don't block: extract request features → NIM (2s timeout) → Ollama (5s timeout) → fail-open. Cache identical requests in Redis (60s TTL).
5. **Request Logger** — buffered async Postgres write (batch every 1s or 100 rows). Push to WebSocket clients.

### AI Service Interface

```go
type AIService interface {
    ClassifyRequest(ctx context.Context, features RequestFeatures) (*Classification, error)
    DetectAnomaly(ctx context.Context, stats TrafficStats) (*AnomalyResult, error)
    GenerateRule(ctx context.Context, attacks []AttackPattern) (*GeneratedRule, error)
    AnalyzeLogs(ctx context.Context, query string) (*AnalysisResult, error)
}
```

Two implementations: `NIMClient` (primary) and `OllamaClient` (fallback). Auto-failover on threshold breach.

### Core Services

- **RuleManager** — load rules from Postgres, cache in memory, hot-reload on change. User-defined + AI-generated rules.
- **LogStore** — buffered async Postgres writer. Batch inserts (100 rows or 1s interval).
- **AnalyticsAggregator** — Redis counters for real-time stats. Periodic Postgres aggregation for historical charts.
- **WebSocketHub** — manages connected dashboard clients, broadcasts events.

### Project Structure

```
waf/
├── cmd/
│   └── waf-engine/
│       └── main.go
├── internal/
│   ├── proxy/          # reverse proxy handler
│   ├── middleware/      # IP check, rate limit, rules, AI classify
│   ├── ai/             # AIService interface + NIM/Ollama implementations
│   ├── rules/          # RuleManager
│   ├── logs/           # LogStore, query
│   ├── analytics/      # AnalyticsAggregator
│   ├── websocket/      # WebSocket hub
│   ├── api/            # REST API handlers
│   └── config/         # config loading
├── dashboard/          # React SPA
├── migrations/         # SQL migrations
├── docker/
│   ├── nginx/
│   ├── waf-engine/
│   └── ollama/
├── config.yaml
├── docker-compose.yml
└── go.mod
```

### Config File (config.yaml)

```yaml
server:
  listen: ":8080"
upstream:
  url: "http://your-app:3000"
ai:
  provider: "nim"  # primary
  nim:
    api_key: "${NIM_API_KEY}"
    model: "meta/llama-3.1-8b-instruct"
    base_url: "https://integrate.api.nvidia.com/v1"
    timeout: 2s
  ollama:
    url: "http://ollama:11434"
    model: "llama3:8b"
    timeout: 5s
  failover:
    threshold: 0.9  # switch to Ollama if NIM success < 90%
    window: 5m
rate_limit:
  default: "100/min"
redis:
  url: "redis://redis:6379"
database:
  url: "postgres://waf:password@postgres:5432/waf"
logging:
  batch_size: 100
  flush_interval: 1s
```

---

## Section 3: Database Schema

### PostgreSQL Tables

```sql
-- WAF rules
CREATE TABLE rules (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    pattern TEXT NOT NULL,
    match_type VARCHAR(50) NOT NULL, -- regex, string, cidr
    action VARCHAR(20) NOT NULL,     -- block, allow, log
    severity VARCHAR(20) NOT NULL,   -- low, medium, high, critical
    priority INT DEFAULT 100,
    enabled BOOLEAN DEFAULT true,
    hit_count BIGINT DEFAULT 0,
    source VARCHAR(50) DEFAULT 'manual', -- manual, ai_generated
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Every request that hits the WAF
CREATE TABLE request_logs (
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
    action VARCHAR(20) NOT NULL,      -- allowed, blocked
    rule_id INT REFERENCES rules(id),
    threat_score FLOAT,
    ai_classification VARCHAR(50),    -- benign, suspicious, malicious
    response_code INT,
    response_time_ms INT,
    country VARCHAR(2),
    asn VARCHAR(50),
    bytes_sent BIGINT,
    bytes_received BIGINT
) PARTITION BY RANGE (timestamp);

-- Monthly partitions (create per month)
CREATE TABLE request_logs_2026_05 PARTITION OF request_logs
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');

-- AI classification results
CREATE TABLE ai_decisions (
    id BIGSERIAL PRIMARY KEY,
    request_id BIGINT,
    model_name VARCHAR(100) NOT NULL,
    provider VARCHAR(20) NOT NULL,  -- nim, ollama
    threat_score FLOAT NOT NULL,
    classification VARCHAR(50) NOT NULL,
    reasoning TEXT,
    latency_ms INT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Detected anomalies
CREATE TABLE anomalies (
    id SERIAL PRIMARY KEY,
    type VARCHAR(50) NOT NULL,       -- traffic_spike, new_endpoint, pattern_shift, geo_anomaly
    severity VARCHAR(20) NOT NULL,
    description TEXT NOT NULL,
    context JSONB,
    resolved BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    resolved_at TIMESTAMPTZ
);

-- Blocked IPs/CIDRs
CREATE TABLE blocked_ips (
    id SERIAL PRIMARY KEY,
    ip_cidr CIDR NOT NULL,
    reason TEXT,
    source VARCHAR(50) DEFAULT 'manual', -- manual, ai_generated, rule_match
    expires_at TIMESTAMPTZ,              -- NULL = permanent
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- AI-generated rule suggestions
CREATE TABLE ai_rule_suggestions (
    id SERIAL PRIMARY KEY,
    pattern TEXT NOT NULL,
    match_type VARCHAR(50) NOT NULL,
    suggested_action VARCHAR(20) NOT NULL,
    confidence FLOAT NOT NULL,
    sample_attacks JSONB,
    status VARCHAR(20) DEFAULT 'pending', -- pending, approved, rejected
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- System config
CREATE TABLE config (
    key VARCHAR(255) PRIMARY KEY,
    value JSONB NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
```

### Redis Usage

- Rate limit counters: `ratelimit:{ip}` with TTL
- AI decision cache: `ai:cache:{request_hash}` with 60s TTL
- Real-time counters: `stats:requests:total`, `stats:requests:blocked`, `stats:requests:allowed` (INCR)
- Top IPs: sorted set `stats:top_ips` (ZINCRBY)
- Top endpoints: sorted set `stats:top_endpoints` (ZINCRBY)
- Active connections: `stats:active_connections`

### Indexing

```sql
CREATE INDEX idx_logs_timestamp ON request_logs (timestamp DESC);
CREATE INDEX idx_logs_client_ip ON request_logs (client_ip);
CREATE INDEX idx_logs_action ON request_logs (action);
CREATE INDEX idx_logs_threat ON request_logs (threat_score) WHERE threat_score > 0.7;
CREATE INDEX idx_blocked_ips_cidr ON blocked_ips USING GIST (ip_cidr);
CREATE INDEX idx_rules_enabled ON rules (enabled) WHERE enabled = true;
```

---

## Section 4: AI Integration

### Provider Config

- **Primary:** NVIDIA NIM — cloud, `integrate.api.nvidia.com`, `meta/llama-3.1-8b-instruct`, 2s timeout
- **Fallback:** Ollama — local, `ollama:11434`, `llama3:8b`, 5s timeout
- **Failover:** Auto-switch when NIM success rate drops below 90% over 5-minute window. Auto-recover.
- **Fail-open:** Both down → allow request, log error.

### Task Routing

| Task | Provider | Trigger | Timeout |
|------|----------|---------|---------|
| Request classification | NIM → Ollama | Every request (if static rules don't block) | 2s / 5s |
| Anomaly detection | NIM | Scheduled batch every 5 min | 30s |
| Rule generation | NIM | On attack cluster detection | 10s |
| Log analysis | NIM → Ollama | On-demand from dashboard | 15s |

### Feature Extraction (lightweight, no full body)

```
method, path, query_params, content_type, user_agent, body_hash, client_ip, country, header_count, param_count
```

### Prompt Template (classification)

```
Analyze this HTTP request for security threats.
Request: {method} {path}?{query}
Content-Type: {content_type}
User-Agent: {user_agent}
Client IP: {client_ip} ({country})
Body hash: {body_hash}

Respond with JSON:
{"score": 0.0-1.0, "classification": "benign|suspicious|malicious", "reasoning": "..."}
```

### Performance

- Only classify requests that pass static rules
- Cache AI decisions in Redis (60s TTL) for identical request hashes
- Batch anomaly detection runs async, doesn't block request path
- Connection pooling for NIM/Ollama HTTP clients

---

## Section 5: Dashboard

### Stack

React 18 + TypeScript, Vite, Tailwind CSS, Recharts, react-simple-maps, TanStack Table, Socket.IO client, React Router, Zustand, Lucide React.

### Theme

Dark mode. Background `#0f172a`, cards `#1e293b`, accent blue-500, danger red-500, warning amber-500, success green-500.

### Pages

#### 1. Overview (default route)
- 4 KPI cards: total requests, blocked requests, active rules, threat score avg
- Real-time traffic line chart (1h/6h/24h/7d toggles)
- Threat donut chart — benign/suspicious/malicious breakdown
- Attack type bar chart — top attack categories by count
- Geo world map — request heat dots by country
- Live request feed — auto-scroll table, color-coded by action

#### 2. Traffic Analytics
- Request volume area chart, stacked by method
- Response code stacked bar chart over time
- Top endpoints table — path, count, avg response time, threat score
- Top IPs table — IP, count, country, threat score, block button
- Bandwidth chart — bytes in/out over time

#### 3. Threat Center
- Attack timeline — severity-weighted events over time
- Attack type horizontal bar with trend arrows
- Severity stacked area over time (low/medium/high/critical)
- Threat event table — filterable, sortable
- AI confidence histogram

#### 4. Rule Management
- Rule table — sortable, filterable by status/severity/source
- Rule editor — create/edit with live pattern testing
- AI suggestion list — approve/reject buttons
- Rule hit stats bar chart
- Enable/disable toggle (hot-reload)

#### 5. AI Panel
- NIM health card — latency, success rate, requests/min
- Ollama health card — same metrics
- AI performance chart — classification latency over time
- Anomaly list — acknowledge/resolve buttons
- Log analyzer — NL text input, AI response display
- Rule generator — describe pattern → AI generates rule

#### 6. Request Logs
- Full-text searchable table with filters
- Log detail modal — full headers, AI reasoning, matched rule
- Filters: date range, IP, path, action, threat score range
- Export: CSV, JSON

#### 7. Settings
- Backend config — upstream URL, rate limits, log retention
- AI config — NIM API key (masked), model, thresholds
- Rate limit settings
- Log retention controls

### Real-time

WebSocket from Go backend. Events: `request`, `block`, `anomaly`, `ai_decision`, `stats` (every 5s), `rule_hit`. Reconnect with exponential backoff.

---

## Section 6: REST API

### Base URL

`/api/v1`. No auth for now.

### Endpoints

#### Dashboard
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/v1/dashboard/overview` | KPIs |
| GET | `/api/v1/dashboard/traffic` | Time-series (range: 1h/6h/24h/7d) |
| GET | `/api/v1/dashboard/threats` | Threat breakdown |
| GET | `/api/v1/dashboard/geo` | Requests by country |
| GET | `/api/v1/dashboard/top-ips` | Top IPs |
| GET | `/api/v1/dashboard/top-endpoints` | Top paths |

#### Real-time
| Method | Path | Purpose |
|--------|------|---------|
| WS | `/api/v1/ws` | Push events |

#### Rules
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/v1/rules` | List (filter: status, severity, source) |
| POST | `/api/v1/rules` | Create |
| PUT | `/api/v1/rules/:id` | Update |
| DELETE | `/api/v1/rules/:id` | Delete |
| PUT | `/api/v1/rules/:id/toggle` | Enable/disable |
| GET | `/api/v1/rules/:id/stats` | Hit stats |
| GET | `/api/v1/rules/suggestions` | AI proposals |
| POST | `/api/v1/rules/suggestions/:id/approve` | Approve |
| POST | `/api/v1/rules/suggestions/:id/reject` | Reject |

#### Blocked IPs
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/v1/blocked-ips` | List |
| POST | `/api/v1/blocked-ips` | Block IP/CIDR |
| DELETE | `/api/v1/blocked-ips/:id` | Unblock |

#### Request Logs
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/v1/logs` | Search/filter |
| GET | `/api/v1/logs/:id` | Detail |
| GET | `/api/v1/logs/export` | CSV/JSON export |

#### AI
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/v1/ai/status` | NIM + Ollama health |
| POST | `/api/v1/ai/analyze` | NL log analysis |
| POST | `/api/v1/ai/generate-rule` | Generate rule from text |
| GET | `/api/v1/anomalies` | List anomalies |
| POST | `/api/v1/anomalies/:id/resolve` | Resolve anomaly |

#### Settings
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/v1/settings` | Current config |
| PUT | `/api/v1/settings` | Update config (partial) |

#### System
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/v1/health` | Health check (no auth) |
| GET | `/api/v1/system/info` | System stats |

### Response Format

```json
// Success
{"success": true, "data": {...}, "meta": {"page": 1, "per_page": 50, "total": 1234}}

// Error
{"success": false, "error": {"code": "NOT_FOUND", "message": "Rule not found"}}
```

### WebSocket Events

```json
{"event": "request", "data": {"id": 123, "client_ip": "1.2.3.4", "method": "GET", "path": "/api/users", "action": "blocked", "threat_score": 0.95, "timestamp": "2026-05-24T10:30:00Z"}}
{"event": "stats", "data": {"total_requests": 5432, "blocked": 123, "avg_threat_score": 0.34}}
{"event": "anomaly", "data": {"id": 1, "type": "traffic_spike", "severity": "high", "description": "..."}}
```

---

## Implementation Phases

### Phase 1: Foundation
- Docker Compose setup (all containers)
- Go project scaffolding + config loading
- PostgreSQL schema + migrations
- Redis connection
- Basic reverse proxy

### Phase 2: WAF Core
- IP reputation middleware
- Rate limiter (Redis-backed)
- Static rule engine
- Request logger (Postgres)
- Rule CRUD API

### Phase 3: AI Integration
- AI Service interface
- NIM client implementation
- Ollama client implementation
- Failover logic
- Classification middleware
- Anomaly detection (scheduled)
- Rule generation
- Log analysis endpoint

### Phase 4: Dashboard
- React project setup (Vite + Tailwind)
- Overview page with real data
- Traffic Analytics page
- Threat Center page
- Rule Management page
- AI Panel page
- Request Logs page
- Settings page

### Phase 5: Real-time
- WebSocket hub (Go)
- Socket.IO client (React)
- Live request feed
- Real-time stat updates
- Anomaly push notifications

### Phase 6: Polish
- Log partition management
- CSV/JSON export
- Error handling hardening
- Performance tuning
- Docker health checks
