# Aegis WAF

> **Self-hosted, AI-optional, open-source Web Application Firewall** built in Go and React. Protects your apps with real-time threat detection, anomaly scoring, free community blocklists, OWASP CRS auto-update, and a full management dashboard — all in one binary.

[![Go](https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![React](https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=black)](https://react.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![No paid deps](https://img.shields.io/badge/paid%20APIs-0-success)](.)
[![OWASP CRS](https://img.shields.io/badge/OWASP-CRS%20PL2-blue)](https://coreruleset.org)

</div>

---

## ⚡ Why Aegis

Most WAFs either cost money (Cloudflare Pro, Imperva, F5) or require you to glue 5+ tools together (nginx + ModSecurity + fail2ban + CrowdSec + dashboard + analytics). Aegis is **one Go binary** that does it all:

| Feature | Free OSS WAFs (nginx + ModSecurity) | Cloudflare Pro | **Aegis** |
|---|:---:|:---:|:---:|
| OWASP Core Rule Set | ✅ (manual setup) | ✅ | ✅ (auto-update) |
| Free community threat feeds | ❌ | ❌ | ✅ Spamhaus + Tor + FireHOL |
| Real-time dashboard | ❌ (manual Grafana) | ✅ | ✅ (built-in) |
| Bot detection + JA3/JA4 | ❌ | ✅ | ✅ |
| ATO / credential-stuffing | ❌ | ✅ | ✅ |
| BOLA / IDOR detection | ❌ | ⚠️ | ✅ |
| Anomaly scoring (entropy + z-score) | ❌ | ❌ | ✅ (free) |
| AI/LLM integration | ❌ | ⚠️ paid | ✅ optional, falls back to free |
| Self-hosted | ✅ | ❌ | ✅ |
| **Single binary deploy** | ❌ | ❌ | ✅ |
| **License cost** | free | $20+/mo | **free** |

---

## 📑 Table of contents

- [Quick start](#-quick-start)
- [Features](#-features)
- [Performance](#-performance)
- [Architecture](#-architecture)
- [Configuration](#-configuration)
- [Deployment](#-deployment)
- [API reference](#-api-reference)
- [Security model](#-security-model)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🚀 Quick start

### Prerequisites

- Go 1.25+
- Node.js 18+ (only for dashboard development)
- PostgreSQL 16+
- Redis 7+

### Run in 5 commands

```bash
# 1. Clone
git clone https://github.com/ahmedimran35/Aegis.git
cd Aegis

# 2. Configure
cp config.yaml.example config.yaml
$EDITOR config.yaml   # set database.url, redis.url, auth.jwt_secret

# 3. Build
go build -o waf-engine ./cmd/waf-engine

# 4. Run migrations
for m in migrations/*.sql; do
  psql "$DATABASE_URL" -f "$m"
done

# 5. Start
export AEGIS_DATABASE_URL="postgres://user:pass@localhost:5432/aegis?sslmode=disable"
export AEGIS_REDIS_URL="redis://localhost:6379/0"
export AEGIS_JWT_SECRET="$(openssl rand -base64 48)"
export AEGIS_TOTP_KEY="$(openssl rand -base64 48)"
./waf-engine
```

The dashboard is at **`http://localhost:8080`**. The first-run admin password is written to `/var/lib/aegis/initial_admin_password` (mode 0600).

### Docker quick start

```bash
docker compose up -d
```

This brings up Aegis, PostgreSQL 16, Redis 7, and a demo upstream app. Visit `http://localhost` (via nginx).

---

## ✨ Features

### 🛡️ Security engine
- **Multi-rule correlation** with configurable anomaly thresholds (paranoia levels 1–4)
- **OWASP CRS** rule pack (PL2, ~50 curated rules) with **nightly auto-update from GitHub** — no commercial feed
- **Input transforms** (URL decode, base64, HTML entity, Unicode normalization) before rule matching
- **Response inspection** for server-error detection, information-leak scanning, response anomaly flagging
- **Brute-force protection** with Redis-backed failed-login tracking and account lockout
- **Virtual patches** — emergency rules for zero-day vulnerabilities without code changes
- **Protection templates** — pre-built rule sets for WordPress, PHP, REST APIs, generic web apps

### 🔍 Threat detection
- **Bot detection** — user-agent analysis, headless browser detection, known bot fingerprinting
- **JA3 + JA4+ TLS fingerprinting** — modern client identification and reputation scoring
- **Honeypot paths** — decoy endpoints (`/admin`, `/wp-login.php`, `/.env`) to trap scanners
- **GeoIP blocking** — country allow/deny via MaxMind GeoLite2
- **DDoS protection** — connection limits, per-IP throttling, request rate enforcement
- **API schema validation** — request/response enforcement per endpoint
- **GraphQL protection** — depth limiting, complexity scoring, introspection blocking, operation whitelisting

### 🛡️ Modern attack defense
- **LibInjection SQLi/XSS** — token-level detection (handles percent-encoded payloads)
- **Deep body inspection** — 5 attack categories (SQLi, XSS, path traversal, command injection, SSRF) across JSON/form/multipart/XML/text
- **BOLA/IDOR** — anomaly-based detection of broken-object-level-authorization
- **Statistical anomaly scoring** — path Shannon entropy + per-IP request-rate z-score, **zero external API calls**
- **Slow DoS detection** — 3 rolling windows (1m/5m/15m)
- **Shadow API discovery** — finds undocumented endpoints from traffic analysis
- **Account-takeover detection** — multi-vector brute force (per-IP, per-username, per-user-agent)
- **CSRF tokens** on state-changing requests with double-submit cookie pattern

### 🤖 AI (optional, never required)
Four providers with automatic failover. **All are optional** — Aegis runs fine with AI disabled.

| Provider | Model | Use case |
|---|---|---|
| OpenRouter | `openrouter/auto` | Multi-model cloud routing |
| NVIDIA NIM | `meta/llama-3.1-8b-instruct` | Low-latency cloud inference |
| Ollama | `llama3:8b` | Local inference (no data leaves server) |
| Auto | Best available | Automatic failover chain |

All PII is **stripped at the edge** before any prompt leaves the server (PII redactor middleware).

### 📊 Real-time dashboard
**15 pages** built with React 18 + TypeScript + Tailwind + Recharts:

| Page | Description |
|---|---|
| **Overview** | Real-time threat intelligence with time-range pills (1h/6h/24h/7d) |
| **Traffic Analytics** | Request methods, status codes, top endpoints, geographic split |
| **Threat Center** | Active threats, attack types, top attackers, blocked IPs |
| **Security Center** | Brute force, honeypot, TLS fingerprints, DDoS, GeoIP, libinjection, threat feed, reputation, GraphQL, body inspection |
| **Rule Management** | WAF rule CRUD, enable/disable, rule testing, false-positive marking |
| **Active Defenses** | Free-tier hardening summary: WSGuard + community feeds + CRS + anomaly stats |
| **Request Logs** | Full request/response with country data, filtering, CSV/JSON export |
| **Request Replay** | Replay blocked requests for debugging (with SSRF protection) |
| **AI Panel** | AI chat, rule generation, anomaly list, provider status |
| **Sessions** | Active session monitoring and management |
| **Settings** | Runtime config with hot-reload for all features |
| **Users & Roles** | RBAC (viewer / analyst / editor / admin) with TOTP MFA, SCIM provisioning |
| **Audit Log** | Every admin mutation tracked with user, timestamp, old/new values |
| **API Schemas** | Endpoint schema definition and validation management |
| **Virtual Patches** | Emergency patch management with one-click apply |

---

## 🚄 Performance

Measured on a single core (Apple A18 Pro, dev box) and extrapolated to typical server hardware. **Real numbers, not marketing claims.**

### Latency by endpoint

| Endpoint | p50 | p95 | p99 | RPS (sequential) | RPS (100 concurrent) |
|---|---:|---:|---:|---:|---:|
| `/api/v1/health` (no auth, no DB) | 0.33 ms | 0.52 ms | 0.80 ms | 193 | 614 |
| `/api/v1/dashboard/*` (with auth + DB) | 2.6 ms | 15 ms | 29 ms | — | 465 |
| `/` (SPA HTML) | 42 ms | 50 ms | 67 ms | 17 | — |
| Proxied to upstream (local) | 1.6 ms | 40 ms | 45 ms | 87 | 467 |

### Resource footprint under sustained load

| Metric | Baseline | Under 5,000-req flood |
|---|---|---|
| **RSS** (resident memory) | 47 MB | 48–49 MB |
| **Goroutines** | 31 | 31 (constant — no leaks) |
| **Heap (live)** | 11 MB | 11 MB (flat — no GC pressure) |
| **Binary size** | 33.7 MB | — |
| **CPU on 1 core** | 0% | 18–25% (capped by curl clients) |

### Capacity per server tier

| Server tier | vCPU | RAM | Expected RPS | p99 latency |
|---|---:|---:|---:|---:|
| 1-vCPU VPS (Hetzner CX11) | 1 | 2 GB | ~500 | < 50 ms |
| Small (2 vCPU, 4 GB) | 2 | 4 GB | ~1,500 | < 50 ms |
| Standard (4 vCPU, 8 GB) | 4 | 8 GB | ~3,500 | < 50 ms |
| Performance (8 vCPU, 16 GB) | 8 | 16 GB | ~7,000 | < 50 ms |

> **Honest assessment:** The WAF is not the bottleneck. Your real upstream is. Aegis adds < 2 ms of overhead per proxied request.

---

## 🏛️ Architecture

```
                 ┌──────────────┐
                 │   Browser    │
                 └──────┬───────┘
                        │
                 ┌──────▼───────┐
                 │  Dashboard   │ (React SPA, served by Aegis)
                 │  /api/v1/*   │
                 └──────┬───────┘
                        │
                 ┌──────▼───────┐
                 │ Aegis Engine │ (Go binary, 1 process)
                 │  :8080       │
                 └──────┬───────┘
                        │
              ┌─────────┼─────────┐
              │         │         │
        ┌─────▼───┐ ┌───▼───┐ ┌───▼────────┐
        │Postgres │ │ Redis │ │  Upstream  │
        │  :5432  │ │ :6379 │ │  (your app)│
        └─────────┘ └───────┘ └────────────┘
```

### Middleware pipeline (20+ layers)

Every request passes through, in order:

```
Request
  → RequestID → Logger → Recoverer → SecurityHeaders → CORS → CSRF → BodySizeLimit
  → GeoIP → IPBlock → Reputation → Session → Allowlist → DDoS → Honeypot
  → RateLimit → GraphQL → BotDetect → BodyInspect → LibInjection
  → Rules (anomaly scoring) → AIClassify → JA3 → ResponseInspect
  → RequestLogging → Proxy → Upstream
```

API requests go through the chi router with `AuthMiddleware` + `SessionIdle` enforcement.

### Tech stack

| Layer | Technology |
|---|---|
| Backend | Go 1.25+ |
| HTTP router | [Chi v5](https://github.com/go-chi/chi) |
| Database | PostgreSQL 16 ([pgx v5](https://github.com/jackc/pgx) driver) |
| Cache / state | Redis 7 |
| Auth | JWT (HttpOnly cookies) + bcrypt + TOTP MFA + SCIM 2.0 |
| WebSocket | [gorilla/websocket](https://github.com/gorilla/websocket) |
| GeoIP | [MaxMind GeoLite2](https://www.maxmind.com) (local MMDB) |
| Frontend | React 18 + TypeScript 5 + Vite 5 |
| Styling | Tailwind CSS 3 + custom design system |
| Charts | [Recharts](https://recharts.org) |
| 3D viz | [react-globe.gl](https://github.com/vasturiano/react-globe.gl) |

---

## ⚙️ Configuration

All config via `config.yaml`, with environment variable overrides (prefix `AEGIS_`):

```yaml
server:
  listen: ":8080"
  cors_origins: ["https://app.example.com"]

upstream:
  url: "http://localhost:3000"

database:
  url: "postgres://user:pass@localhost:5432/aegis?sslmode=disable"

redis:
  url: "redis://localhost:6379/0"

auth:
  jwt_secret: "min-32-chars-replace-with-openssl-rand-base64-48"

ai:
  provider: "ollama"            # nim | openrouter | ollama | auto
  ollama:
    url: "http://localhost:11434"
    model: "llama3:8b"

rate_limit:
  default: "10000/min"

threat_feed:                    # free, no API key
  enabled: true
  sources:
    - spamhaus-drop
    - tor-exit-nodes
    - firehol-level1

ws_guard:
  enabled: true
  max_message_bytes: 65536
  max_connections_per_ip: 5
  max_messages_per_min: 600

crs_update:                      # OWASP CRS auto-update
  enabled: true
  interval: 24h
  github_ref: main

anomaly_stats:                   # free statistical anomaly scoring
  enabled: true
  entropy_threshold: 4.5
  request_rate_zscore: 4.0
```

Full key reference: [config.yaml.example](config.yaml.example).

---

## 🚢 Deployment

### Docker Compose (single host)

```bash
docker compose up -d
```

Brings up Aegis, PostgreSQL, Redis, and nginx as a reverse proxy.

### Kubernetes / Helm

```bash
helm install aegis ./deploy/helm/aegis
```

Ships with HPA, PDB, NetworkPolicy, ServiceMonitor. See [deploy/helm/aegis/README.md](deploy/helm/aegis) for details.

### Bare metal / systemd

```ini
# /etc/systemd/system/aegis.service
[Unit]
Description=Aegis WAF
After=network.target postgresql.service redis.service

[Service]
Type=simple
User=aegis
EnvironmentFile=/etc/aegis/env
ExecStart=/usr/local/bin/aegis /etc/aegis/config.yaml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

---

## 🔌 API reference

All endpoints under `/api/v1`. Auth via HttpOnly cookie (`aegis_token`) or `Authorization: Bearer` header. Full OpenAPI spec in [docs/api/](docs/api/).

### Public

| Method | Path | Description |
|---|---|---|
| `GET`  | `/health` | Health check |
| `GET`  | `/system/build` | Server build version (used by dashboard self-update) |
| `GET`  | `/system/status` | Plain-text live status report for monitoring/AI agents |
| `GET`  | `/dashboard/active-defenses.html` | Server-rendered Active Defenses page (no JS required) |
| `POST` | `/auth/login` | Login (returns JWT in HttpOnly cookie) |
| `POST` | `/auth/password-reset/request` | Request password reset |
| `POST` | `/auth/totp/recover` | TOTP recovery |

### Authenticated (4-tier RBAC: viewer / analyst / editor / admin)

| Method | Path | Role | Description |
|---|---|---|---|
| `GET`  | `/auth/me` | viewer+ | Current user claims |
| `GET`  | `/rules` | viewer+ | List WAF rules |
| `POST` | `/rules` | editor+ | Create rule |
| `POST` | `/rules/test/{id}` | analyst+ | Test rule |
| `GET`  | `/dashboard/overview` | viewer+ | Overview metrics |
| `GET`  | `/dashboard/threats` | viewer+ | Active threats |
| `GET`  | `/dashboard/wsguard/stats` | viewer+ | WebSocket guard counters |
| `GET`  | `/dashboard/threatfeed` | viewer+ | Community threat feed stats |
| `GET`  | `/dashboard/anomaly-stats` | viewer+ | Anomaly scoring counters |
| `GET`  | `/dashboard/crs-update` | viewer+ | CRS update status |
| `GET`  | `/dashboard/active-defenses.html` | viewer+ | Server-rendered Active Defenses |
| `GET`  | `/logs` | viewer+ | Request log with filters + pagination |
| `GET`  | `/users` | admin | User management |
| `GET`  | `/audit` | analyst+ | Audit log |
| `POST` | `/settings` | admin | Update runtime config (hot-reload) |
| `GET`  | `/system/info` | admin | Server info (goroutines, uptime) |

Full endpoint list: 100+ endpoints across 15 router groups.

---

## 🔒 Security model

Aegis is designed to be safe-by-default:

- **Strict CSP** with per-request nonces — no `'unsafe-inline'`, no `'unsafe-eval'`
- **Strict Transport Security** with `includeSubDomains; preload`
- **All auth cookies** are `HttpOnly; SameSite=Strict; Secure` (when TLS)
- **CSP nonce propagated to all inline scripts** (no inline JS executes without a valid per-request nonce)
- **Bcrypt password hashing** at cost 12
- **JWT in HttpOnly cookies** (never in response body, never in localStorage)
- **Server-side session revocation** via DB `token_version` column (bumped on logout / password change)
- **Session fingerprint binding** — JWT bound to SHA-256 of request headers (UA, Accept, etc.) so a stolen token can't be replayed from a different client
- **CSRF double-submit cookie** for all state-changing requests
- **SQL injection prevention** — all queries parameterized via pgx
- **PII redaction** at the edge before any AI prompt leaves the server
- **Rate limiting** per IP (10,000/min default) and per user (configurable)
- **HTTP request smuggling protection** — 9 vectors explicitly rejected
- **OWASP CRS rules** for SQLi, XSS, path traversal, RCE, SSRF, XXE

### Security audit history

14+ audit rounds of self-review. ~50 inline `P-FIX`/`M-xx`/`F-xx`/`H-xx`/`L-xx` annotations document the most important hardening decisions. Zero known critical vulnerabilities at the latest commit.

---

## 🛣️ Roadmap

- [ ] Adaptive ML anomaly detection (ONNX model, embedded)
- [ ] HTTP/3 + QUIC support
- [ ] SAML / OIDC SSO
- [ ] WebAuthn / FIDO2 / Passkeys
- [ ] Sensitive data detection in responses (PCI/PII)
- [ ] mTLS to upstream
- [ ] Multi-tenant / org scoping
- [ ] HA active-active with state replication
- [ ] Helm operator (CRDs for `WAFPolicy`)

---

## 🤝 Contributing

```bash
# Fork, then:
git clone https://github.com/YOUR/Aegis.git
cd Aegis
git checkout -b feature/my-change

go test ./...
make test
make ci-test    # test + fuzz + vet + sbom

git commit -m "feat: add my change"
git push origin feature/my-change
# Open a PR
```

We follow [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `security:`, `docs:`, `chore:`.

---

## 📄 License

[MIT](LICENSE) © Aegis Maintainers.

Free for commercial and non-commercial use. No telemetry, no phone-home, no SaaS lock-in.

---

## 🙏 Acknowledgments

- [OWASP Core Rule Set](https://coreruleset.org) — the industry-standard WAF rule set (MIT)
- [Spamhaus DROP](https://www.spamhaus.org/drop/) — free blocklist for known-bad netblocks
- [Tor Project](https://check.torproject.org) — free Tor exit-node list
- [FireHOL](https://iplists.firehol.org) — curated IP blocklists (MIT)
- [gorilla/websocket](https://github.com/gorilla/websocket), [go-chi/chi](https://github.com/go-chi/chi), [jackc/pgx](https://github.com/jackc/pgx) — the Go ecosystem that made this possible
