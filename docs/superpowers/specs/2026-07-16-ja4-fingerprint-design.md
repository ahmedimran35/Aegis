# Aegis JA4 Fingerprint Middleware — Design Spec

**Date:** 2026-07-16
**Workstream:** WS1
**Status:** Draft

## 1. Goal

Ship a true JA4-family TLS-client fingerprint middleware that:
- Matches the FoxIO JA4 spec (JA4 + JA4-H)
- Captures H/2 SETTINGS entropy (extension to JA4 family)
- Computes header-order entropy (already exists as HeaderFingerprint)
- Feeds fingerprint signals into the existing `behavioral_score.go` as a SCORE SIGNAL ONLY (no hard block on first request)
- Replaces the "ja3like-" stub with a real hash that survives review

## 2. Background — what's already there

- `internal/middleware/headerfp.go:60` — `ComputeJA3` produces "ja3like-" prefix, NOT spec-compliant (Go's `crypto/tls` doesn't expose raw ClientHello extensions/curves/point formats)
- `internal/middleware/headerfp.go:86` — `HeaderFingerprint` produces "hf-" hash from UA + Accept + Accept-Encoding + Accept-Language + Sec-Ch-Ua family
- `internal/middleware/headerfp.go:165` — `JA3Checker.Middleware` stores fingerprint, looks up reputation, blocks on "blocked" reputation
- `internal/middleware/h2fp.go` — H/2 hint-based hash (P2-F1); acknowledges real H/2 fingerprinting needs SETTINGS frame bytes which Aegis can't see
- `internal/middleware/behavioral_score.go` — bot scoring logic that consumes header fingerprint signals

Round 25+ removed JA3 spec-compliant impl because Go can't read raw ClientHello. Round 32+ needs to bridge this with JA4 + JA4-H which DOES work at the Go std-lib level.

## 3. JA4 spec recap

JA4 fingerprint format (FoxIO):

```
JA4 = {proto}{version}{SNI}{count}{ALPN}{cipher_hash}{ext_hash}
JA4-H = JA4 + "-" + {header_order_hash}
```

Where:
- `proto`: t (TCP), q (QUIC), u (UDP) — we use `t`
- `version`: TLS version (e.g. `13`, `12`)
- `SNI`: `i` (SNI present) or `x` (no SNI)
- `count`: 2-digit count of cipher suites
- `ALPN`: first ALPN value (e.g. `h2`, `http1`)
- `cipher_hash`: 12-char truncated SHA256 of sorted cipher suite hex
- `ext_hash`: 12-char truncated SHA256 of sorted extension hex

All values that can be extracted from `crypto/tls.ConnectionState` are available. The list of extensions + supported_groups + signature_algorithms is NOT in `ConnectionState` (Go limitation).

JA4-H adds a hash of the request header ORDER (not values), e.g.:

```
Header order: Host,User-Agent,Accept,Accept-Language,Accept-Encoding
→ SHA256(sorted lowercase header names, first 12 hex chars)
```

## 4. Architecture

### 4.1 New file: `internal/middleware/ja4.go`

Pure functions, no middleware wrapper. Reusable from JA3Checker.Middleware.

```go
// JA4Components holds the raw JA4 input values for hashing.
type JA4Components struct {
    TLSVersion    uint16          // state.Version
    CipherSuites  []uint16        // sorted; extracted via reflect on ClientHello? NO — go std lib exposes only negotiated cipher
    Extensions    []uint16        // NOT exposed by Go — see Limitations
    SNI           string          // state.ServerName
    ALPN          string          // state.NegotiatedProtocol
}

// JA4Result is the parsed JA4 string + components for downstream use.
type JA4Result struct {
    Raw        string // "t13i1508h2_8daaf6152771_b0da82dd1658" (JA4 family uses _)
    JA4H       string // JA4-H including header-order entropy
    Components JA4Components
}

// ComputeJA4 computes a JA4-family fingerprint from a TLS connection state.
// Returns ("", error) if state is nil or no usable signals.
//
// LIMITATION: Go std lib exposes only Version + NegotiatedCipherSuite +
// NegotiatedProtocol + ServerName. The full JA4 spec requires cipher suite
// LIST + extensions + supported_groups from the ClientHello. We compute
// a JA4-LIKE hash using the exposed fields and label the prefix `ja4-`
// (not `JA4:`) so consumers understand the partial nature.
//
// For spec-compliant JA4, deploy an eBPF probe or sidecar that captures
// raw ClientHello bytes (see DEPLOY.md).
func ComputeJA4(state *tls.ConnectionState) (*JA4Result, error)

// ComputeJA4H computes the JA4-H header-order entropy hash for an HTTP
// request. Lowercase header names, sorted, joined with ",", SHA256-prefix.
func ComputeJA4H(r *http.Request) string

// JA4Middleware returns an http.Handler middleware that:
//  1. Computes JA4 from r.TLS (if present) → context value
//  2. Computes JA4-H from request headers → context value
//  3. Stores fingerprint async (existing tls_fingerprints table)
//  4. Looks up reputation; if "blocked", returns 403 (existing behavior)
//  5. NEVER hard-blocks on first request — score signal only
func JA4Middleware(pool *pgxpool.Pool, scorer *BehavioralScorer) func(http.Handler) http.Handler
```

### 4.2 Replace `internal/middleware/headerfp.go` JA3 paths

- `ComputeJA3` → marked Deprecated, calls `ComputeJA4`, returns "ja4-" prefix
- `ExtractJA3FromConn` → marked Deprecated, calls JA4 path
- `JA3Checker.Middleware` → renamed to `JA4Checker` (or alias kept for compat)
- Context keys `ja3HashKey` / `ja3ReputationKey` → `ja4HashKey` / `ja4ReputationKey`, old keys kept as aliases for downstream readers during deprecation window

### 4.3 Wire into `behavioral_score.go`

Add scoring weights:
- Known-bad JA4 fingerprint (e.g., `python-requests/2.x` default): +25
- JA4-H entropy < 1.5 bits/char (suspiciously uniform header set): +15
- JA4-H entropy > 4.5 (too diverse, random padding): +10
- Combined with existing UA entropy + digit ratio + behavioral signals

### 4.4 Database migration

`migrations/022_ja4_support.up.sql`:
```sql
ALTER TABLE tls_fingerprints
  ADD COLUMN ja4_hash TEXT,
  ADD COLUMN ja4_h TEXT,
  ADD COLUMN proto TEXT NOT NULL DEFAULT 'tcp';

CREATE INDEX IF NOT EXISTS idx_tls_fp_ja4_hash
  ON tls_fingerprints (ja4_hash)
  WHERE ja4_hash IS NOT NULL;

UPDATE tls_fingerprints
  SET ja4_hash = substring(ja3_hash FROM '..[^.]*$')
  WHERE ja3_hash LIKE 'ja4-%' OR ja3_hash LIKE 'ja3like-%';
```

(Down migration renames columns back. JA3 columns kept for audit history.)

## 5. Limitations — explicit

1. **Go std-lib can't read raw ClientHello.** Cipher suite LIST + extension list + supported_groups + point formats are not in `tls.ConnectionState`. JA4 produced is a JA4-LIKE hash with "ja4-" prefix. Spec-compliant JA4 requires:
   - eBPF/XDP probe, OR
   - Sidecar proxy that captures raw bytes, OR
   - Patch Go's `crypto/tls` (out of scope)

2. **No H/2 SETTINGS frame capture.** Aegis sits above H/2 layer. We accept this and use H/2 client-hint headers + JA4-H as proxy. Documented in `docs/DEPLOY.md`.

3. **Reputation lookup adds 1 SQL roundtrip.** Acceptable for hot path (P95 < 5ms with Redis cache; currently <2ms in existing JA3 path).

## 6. Error handling

- Nil `tls.ConnectionState` → return `("", nil)` (cleartext, will fall through to JA4-H)
- Empty cipher suite / SNI → still produce hash with empty fields, prefixed `ja4-empty-`
- DB store failure → log + continue, do NOT block request
- Reputation lookup failure → return "unknown", do NOT block (fail-OPEN for FP reputation, NOT for security middleware)

## 7. Testing

`internal/middleware/ja4_test.go`:
1. ComputeJA4 on known TLS state produces stable hash (table-driven: Chrome, Firefox, curl, python-requests)
2. ComputeJA4H on known header order produces stable hash
3. JA4Middleware stores fingerprint async + sets context
4. JA4Middleware with reputation="blocked" returns 403
5. JA4Middleware with nil TLS still computes JA4-H
6. BehavioralScorer integration: known-bad JA4 + low entropy UA → score > threshold

`internal/middleware/ja4_fuzz_test.go`:
- Fuzz ComputeJA4 with random tls.ConnectionState — must not panic, must produce stable hash for same input
- Fuzz ComputeJA4H with random header order — same

## 8. Rollout

1. Land spec + impl + tests + migration in single PR
2. Add metric `ja4_computed_total{proto,version}` Prometheus counter
3. Dashboard widget: "JA4 fingerprints seen (24h)" + top 10 known-bad
4. Document partial nature in README + DEPLOY.md so users know what they're getting

## 9. Out of scope

- eBPF probe for raw ClientHello (deferred to WS3 or external)
- Sidecar proxy for full JA4 (deferred)
- JA4S (server) / JA4H (HTTP/2) — JA4-L + JA4H cover our needs
- ML model on top of JA4 distribution (deferred to WS2 if scope permits)