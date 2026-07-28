# Top-10 WAF Production Fixes — 2026-06-26

## Goal

Close the 5 CRIT + 5 HIGH gaps from the readiness audit, scored 6.5/10 → 8.5/10.

## Constraints

- Touch only files needed for the fix. No opportunistic refactoring.
- Preserve `internal/tls/autocert.go` (existing but unwired).
- Preserve existing tests; add new tests for new behavior.
- Build green after every fix.
- No new 3rd-party deps unless required (Prometheus = exception).

## Fix Order (by dependency)

| # | Fix | Files | Deps |
|---|---|---|---|
| 1 | TLS wire + HTTPS redirect + HSTS + cipher list | `cmd/waf-engine/main.go`, `internal/tls/autocert.go`, `internal/config/config.go` | — |
| 2 | Redis Sentinel/Cluster + persistence config | `internal/db/redis.go`, `internal/config/config.go`, `docker-compose.yml` | — |
| 3 | Rule engine Evaluate() transforms + paranoia | `internal/rules/engine.go`, `internal/rules/transforms.go` | — |
| 4 | Real JA3 from TLS ClientHello | `internal/middleware/ja3.go` | — |
| 5 | Numeric SQLi tokenization | `internal/middleware/libinjection.go` | — |
| 6 | Feedback → rule auto-create | `internal/api/feedback.go`, migrations/010 | — |
| 7 | Prometheus /metrics | `internal/metrics/`, `internal/api/router.go`, `go.mod`, `cmd/waf-engine/main.go` | new dep |
| 8 | GDPR retention + export/delete + PII redact | `internal/gdpr/`, `internal/api/router.go`, `internal/logs/logger.go` | — |
| 9 | Global MaxBytesReader + smuggling checks | `internal/middleware/limits.go` (new), `cmd/waf-engine/main.go` | — |
| 10 | (rolled into #1) HTTPS redirect + cipher list + HSTS | — | — |

## Fix 1+10: TLS, HTTPS Redirect, HSTS, Cipher List

**Why:** Server runs `ListenAndServe` (plain HTTP). TLS code in `internal/tls/autocert.go` never imported. No HSTS header anywhere.

**Changes:**

1. `internal/tls/autocert.go`:
   - Add `CipherSuites` field to `Config` + `TLSConfig()`.
   - Add `HSTSHeader()` middleware that sets `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`.
   - Add `CipherSuites` (modern ECDHE-only): `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`, `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`, `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305`, `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305`, `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`, `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`.
   - MinVersion stays `TLS 1.2`. (Note: prefer `TLS 1.3` but `autocert` requires 1.2 for compat.)

2. `cmd/waf-engine/main.go`:
   - Import `github.com/user/waf/internal/tls` (rename package collision: use alias `wafstls`).
   - When `cfg.TLS.Enabled` is true:
     - Build `tlsManager := wafstls.NewManager(cfg.TLS.Config())`.
     - Wrap mux with `wafstls.HSTSHeader` middleware.
     - Replace `ListenAndServe` with `ListenAndServeTLS` (or use `StartServers` from autocert.go).
     - Add 301 redirect handler for `cfg.Server.Listen` (typically `:80`) → HTTPS.
   - When `cfg.TLS.Enabled` is false (dev), keep `ListenAndServe` but still apply HSTS header (it's harmless on HTTP).

3. `internal/config/config.go`:
   - Add `TLSConfig` struct with `Enabled`, `Domains`, `Email`, `CacheDir`, `HTTPSAddr`, `HTTPAddr`, `HSTSEnabled`, `HSTSMaxAge`, `RedirectHTTP`.
   - Add `tls:` section to `config.yaml` + `config.yaml.example`.

**Verify:** `grep -n "TLSConfig\|HSTS\|CipherSuites" cmd/waf-engine/main.go` shows them.

## Fix 2: Redis Sentinel + Persistence

**Why:** Redis is SPOF for brute-force, rate-limit, session. Restart = bypassable.

**Changes:**

1. `internal/db/redis.go`:
   - Add `SentinelAddrs []string` + `MasterName string` fields to `RedisConfig`.
   - In `NewRedis`: if SentinelAddrs non-empty, use `redis.NewFailoverClient(&redis.FailoverOptions{...})`.
   - Keep `NewRedis` signature backward-compatible.

2. `internal/config/config.go`:
   - Add `Sentinel` section to RedisConfig: `enabled`, `addrs`, `master_name`.

3. `docker-compose.yml`:
   - Add `redis-sentinel` service with `redis:7-alpine` + `sentinel.conf`.
   - Add `command:` to redis service enabling AOF: `--appendonly yes`.
   - Add volumes for `/data`.

**Verify:** Compose has `redis-sentinel`, `appendonly yes`.

## Fix 3: Rule Engine Evaluate() with Transforms + Paranoia

**Why:** `Evaluate()` (first-match) doesn't apply transforms or filter by paranoia. Production uses `EvaluateAll` but legacy callers + new callers may use `Evaluate` and miss attacks.

**Changes:**

1. `internal/rules/engine.go`:
   - Refactor `Evaluate()` to:
     - Filter by `r.ParanoiaLevel <= paranoiaLevel` (accept new param).
     - Build inputs list same as `EvaluateAll` (raw + transformed).
     - Match against inputs.
   - Keep signature backward-compatible by accepting `(...paranoiaLevel int)`. Use variadic? No — break signature. Callers: search and update.
   - Callers of `Evaluate`: `grep -rn "Evaluate(" internal/`.

**Verify:** `engine.go:184` `Evaluate` checks `r.ParanoiaLevel > paranoiaLevel` and calls `ApplyTransforms`.

## Fix 4: Real JA3 from TLS ClientHello

**Why:** Current implementation hashes ServerName (placeholder) + empty curves + empty point formats. Useless for bot detection.

**Changes:**

1. `internal/middleware/ja3.go`:
   - Replace fake JA3 with HTTP-header fingerprint as fallback.
   - Capture: `User-Agent`, `Accept`, `Accept-Encoding`, `Accept-Language` hash (JA3-like "browser fingerprint" since Go TLS API doesn't expose ClientHello raw).
   - Add SHA-256 of concatenated values, formatted as `v1=<hash>` for clarity it's not real JA3.
   - Document in comment: "Go's tls.Conn doesn't expose raw ClientHello bytes; this is an HTTP-header fingerprint that approximates JA3 use cases."
   - OR: implement packet-level sniffing on the listener (complex, may break proxy model).

**Decision:** Implement HTTP-header fingerprint (good enough for bot detection; clearly labeled as JA3-like, not real JA3). Add deprecation note.

**Verify:** `ja3.go` does NOT reference `ServerName` as input.

## Fix 5: Numeric SQLi Tokenization

**Why:** `libinjection.go:380` numeric SQLi (`1=1`, `OR 1=1`) not tokenized.

**Status from Round 16 audit:** **ALREADY PASS** per Round 16 audit. Verify in current tree.

**Verify:** `libinjection.go:272` shows `unicode.IsDigit` tokenization.

## Fix 6: Feedback → Rule Auto-Create

**Why:** `feedback.go:99` FN handler only calls `policyTuner.RecordFN`. No DB INSERT, no rule generation. FP/FN data is lost.

**Changes:**

1. `migrations/010_feedback_rule_auto.sql` (new):
   - Add column `auto_rule_id INT NULL` to `false_positives`, `false_negatives` tables.

2. `internal/api/feedback.go`:
   - In `FalseNegative` handler: after `policyTuner.RecordFN`, INSERT into `false_negatives` (log_id, path, payload, created_by).
   - Generate a new rule from the offending pattern:
     - `name = "auto-fn-{timestamp}"`
     - `pattern = <escaped payload>` (string match for safety; or basic regex)
     - `match_type = "string"`
     - `action = "block"`
     - `severity = "medium"`
     - `paranoia_level = 1`
     - `source = "auto-feedback"`
     - INSERT into `rules` table.
   - Update `false_negatives.auto_rule_id` with new rule ID.
   - Call `ruleEngine.Reload()` to pick up new rule.
   - Similar for FP handler — but FP creates an "allow" rule.

3. `internal/api/feedback.go` — wire `ruleEngine` reference into handler constructor.

**Verify:** `feedback.go:99-128` writes to DB + creates rule + reloads engine.

## Fix 7: Prometheus /metrics

**Why:** No metrics endpoint. Operators blind to throughput, error rates, AI latency.

**Changes:**

1. `go.mod`: add `github.com/prometheus/client_golang`.

2. `internal/metrics/metrics.go` (new):
   - Define counters: `aegis_requests_total`, `aegis_blocks_total`, `aegis_rate_limit_drops_total`, `aegis_ai_classify_total`, `aegis_ai_classify_errors_total`, `aegis_brute_force_locks_total`.
   - Define histograms: `aegis_request_duration_seconds`, `aegis_ai_classify_duration_seconds`.
   - Define gauges: `aegis_active_connections`, `aegis_rule_count`.
   - Expose `Handler()` returning `promhttp.Handler()`.

3. `internal/api/router.go`:
   - Add route `/metrics` (unauthenticated, but bound to localhost via `http.ServeMux` pattern).

4. `cmd/waf-engine/main.go`:
   - Initialize metrics.
   - Wire into middleware (rule, rate-limit, AI, brute-force counters).

**Verify:** `grep prometheus/client_golang go.mod` + `grep "/metrics" internal/api/router.go`.

## Fix 8: GDPR: Retention + Export/Delete + PII Redact

**Why:** Full headers logged including PII. No data retention enforcement. No GDPR export/delete endpoints.

**Changes:**

1. `internal/logs/logger.go`:
   - Add `RedactPII(s string) string`: replace emails with `[REDACTED]`, IPs with last octet zeroed, paths containing common PII (e.g. `/user/\d+/`) with `[REDACTED_USER]`.
   - Apply `RedactPII` to `headers`, `query`, `body` fields before DB write.

2. `internal/gdpr/retention.go` (new):
   - Worker goroutine running on `cfg.Logging.FlushInterval * 12` (e.g. hourly).
   - DELETE FROM request_logs WHERE created_at < NOW() - INTERVAL '... days'.
   - DELETE FROM audit_log WHERE created_at < NOW() - INTERVAL '... days'.
   - Honors `cfg.Logging.RetentionDays` (new config field).

3. `internal/api/router.go`:
   - `GET /api/v1/gdpr/export` (admin): dump all data for current user as JSON.
   - `POST /api/v1/gdpr/delete` (admin): DELETE all data for current user.

4. `internal/config/config.go`:
   - Add `Logging.RetentionDays` (default 30).

**Verify:** `internal/gdpr/retention.go` exists; `RedactPII` used in logger; `/gdpr/export` route.

## Fix 9: Global MaxBytesReader + Smuggling Checks

**Why:** No global request size limit. Body inspection is per-middleware but base request is unbounded. Smuggling via CL/TE conflict undetected.

**Changes:**

1. `internal/middleware/limits.go` (new):
   - `MaxBytesMiddleware(maxBytes int64)` wraps `r.Body = http.MaxBytesReader(w, r.Body, maxBytes)`.
   - `SmugglingCheckMiddleware`: reject requests with BOTH `Content-Length` AND `Transfer-Encoding: chunked` (HTTP/1.1 spec ambiguity = smuggling vector).

2. `cmd/waf-engine/main.go`:
   - Add both middlewares to the pipeline (outermost position).

**Verify:** `cmd/waf-engine/main.go` pipeline includes `MaxBytesMiddleware` and `SmugglingCheckMiddleware`.

## File-Level Edit List

| File | New? | Edits |
|---|---|---|
| `cmd/waf-engine/main.go` | — | import tls pkg, add HSTS middleware, switch to ListenAndServeTLS, add MaxBytes+Smuggling, metrics wire, gdpr worker start |
| `internal/tls/autocert.go` | — | CipherSuites, HSTSHeader, dev-mode HTTPSRedirect |
| `internal/config/config.go` | — | TLSConfig, Redis.Sentinel, Logging.RetentionDays |
| `internal/db/redis.go` | — | Sentinel/Cluster support |
| `internal/rules/engine.go` | — | Evaluate() with paranoia + transforms |
| `internal/middleware/ja3.go` | — | HTTP-header fingerprint |
| `internal/api/feedback.go` | — | INSERT + rule auto-create + engine reload |
| `internal/middleware/libinjection.go` | verify only | (already done per audit) |
| `internal/metrics/metrics.go` | new | Prometheus definitions |
| `internal/api/router.go` | — | /metrics, /gdpr/export, /gdpr/delete |
| `internal/gdpr/retention.go` | new | retention worker |
| `internal/logs/logger.go` | — | RedactPII |
| `internal/middleware/limits.go` | new | MaxBytes + Smuggling |
| `go.mod` | — | add prometheus dep |
| `docker-compose.yml` | — | redis sentinel, AOF |
| `migrations/010_feedback_rule_auto.sql` | new | auto_rule_id column |
| `config.yaml`, `config.yaml.example` | — | tls section, retention, sentinel |

Total: 13 modified, 4 new.

## Verification Plan

After all 10 fixes:
1. `go build ./...` — must pass
2. `go vet ./...` — must pass
3. `go test ./...` — existing tests must pass
4. Spawn verify agent with this checklist → expect 10 PASS
5. Spot-check: `curl http://localhost:8080/metrics` returns Prometheus output
6. Spot-check: `curl -I https://localhost:8443/` returns HSTS header

## Risk + Rollback

- TLS change risks startup if certs missing: gate on `cfg.TLS.Enabled`.
- Prometheus dep adds ~5MB to binary. Acceptable.
- Retention worker is destructive: default 30 days, configurable.
- Rule auto-create from FP/FN: potential for runaway rule count — add cap (max 1000 auto rules, oldest evicted).
