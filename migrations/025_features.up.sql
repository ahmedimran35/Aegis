-- ===========================================================================
-- Features 4-12 backend tables
-- ===========================================================================

-- #4 JWT allowlist: explicitly permit alg values (default: ['HS256']).
-- Anything else gets rejected at the edge. K-V pairs of (alg, issuer) so
-- we can permit different algs for different issuers.
CREATE TABLE IF NOT EXISTS jwt_allowlist (
  id            SERIAL PRIMARY KEY,
  alg           VARCHAR(20) NOT NULL,
  issuer        TEXT NOT NULL DEFAULT '*',
  enabled       BOOLEAN NOT NULL DEFAULT true,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (alg, issuer)
);
INSERT INTO jwt_allowlist (alg, issuer, enabled) VALUES
  ('HS256', '*', true), ('HS384', '*', true), ('HS512', '*', true),
  ('RS256', '*', true), ('RS384', '*', true), ('RS512', '*', true),
  ('ES256', '*', true), ('ES384', '*', true), ('ES512', '*', true),
  ('PS256', '*', true), ('PS384', '*', true), ('PS512', '*', true),
  ('EdDSA', '*', true)
ON CONFLICT (alg, issuer) DO NOTHING;

-- #7 CVE virtual-patch feed
CREATE TABLE IF NOT EXISTS cve_feed (
  id            SERIAL PRIMARY KEY,
  cve_id        VARCHAR(20) NOT NULL UNIQUE,
  cvss_score    REAL,
  severity      VARCHAR(20) NOT NULL DEFAULT 'medium',
  affected_product TEXT,
  rule_pattern  TEXT NOT NULL,
  rule_action   VARCHAR(20) NOT NULL DEFAULT 'block',
  rule_match    VARCHAR(20) NOT NULL DEFAULT 'regex',
  description   TEXT,
  published_at  TIMESTAMPTZ,
  auto_apply    BOOLEAN NOT NULL DEFAULT false,
  applied_at    TIMESTAMPTZ,
  virtual_patch_id INT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- #5 per-endpoint anomaly baseline (sliding window counts)
CREATE TABLE IF NOT EXISTS endpoint_anomaly (
  id            BIGSERIAL PRIMARY KEY,
  path          TEXT NOT NULL,
  method        VARCHAR(10) NOT NULL,
  window_start  TIMESTAMPTZ NOT NULL,
  total         INT NOT NULL DEFAULT 0,
  blocked       INT NOT NULL DEFAULT 0,
  p95_latency_ms INT NOT NULL DEFAULT 0,
  bytes_total   BIGINT NOT NULL DEFAULT 0,
  UNIQUE (path, method, window_start)
);
CREATE INDEX IF NOT EXISTS idx_endpoint_anomaly_path_time ON endpoint_anomaly (path, method, window_start DESC);

-- #5 anomaly events (when a window breaches baseline)
CREATE TABLE IF NOT EXISTS endpoint_anomaly_events (
  id            BIGSERIAL PRIMARY KEY,
  path          TEXT NOT NULL,
  method        VARCHAR(10) NOT NULL,
  observed_qps  REAL NOT NULL,
  baseline_qps  REAL NOT NULL,
  multiplier    REAL NOT NULL,
  severity      VARCHAR(20) NOT NULL DEFAULT 'low',
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_endpoint_anomaly_events_time ON endpoint_anomaly_events (created_at DESC);

-- #6 browser-challenge issued nonces (PoW)
CREATE TABLE IF NOT EXISTS browser_challenge (
  id            BIGSERIAL PRIMARY KEY,
  token         VARCHAR(64) NOT NULL UNIQUE,
  ip            INET NOT NULL,
  user_agent    TEXT,
  expires_at    TIMESTAMPTZ NOT NULL,
  solved        BOOLEAN NOT NULL DEFAULT false,
  solved_at     TIMESTAMPTZ,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_browser_challenge_expires ON browser_challenge (expires_at);

-- #3 LLM endpoint protection: rules table
CREATE TABLE IF NOT EXISTS llm_protection_rules (
  id            SERIAL PRIMARY KEY,
  name          TEXT NOT NULL,
  pattern       TEXT NOT NULL,
  kind          VARCHAR(30) NOT NULL,  -- 'prompt_injection','jailbreak','oversized','pii_leak','system_prompt_leak'
  action        VARCHAR(20) NOT NULL DEFAULT 'block',
  enabled       BOOLEAN NOT NULL DEFAULT true,
  hits          INT NOT NULL DEFAULT 0,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- #11 file-upload scans (record of magic-bytes detection)
CREATE TABLE IF NOT EXISTS upload_scans (
  id            BIGSERIAL PRIMARY KEY,
  ip            INET,
  content_type  VARCHAR(100),
  filename      TEXT,
  size_bytes    INT NOT NULL,
  detected_magic VARCHAR(50),
  verdict       VARCHAR(20) NOT NULL,  -- 'allow','block','quarantine'
  matched_rule  TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- #1 OpenAPI schemas
CREATE TABLE IF NOT EXISTS openapi_schemas (
  id            SERIAL PRIMARY KEY,
  name          TEXT NOT NULL UNIQUE,
  spec          JSONB NOT NULL,
  version       VARCHAR(20),
  paths_count   INT NOT NULL DEFAULT 0,
  enabled       BOOLEAN NOT NULL DEFAULT true,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- #2 ATO credential-stuffing events (per-account pattern)
CREATE TABLE IF NOT EXISTS credential_stuffing_events (
  id            BIGSERIAL PRIMARY KEY,
  ip            INET NOT NULL,
  username      TEXT NOT NULL,
  distinct_users_count INT NOT NULL,
  attempt_count INT NOT NULL,
  status        VARCHAR(20) NOT NULL DEFAULT 'detected',
  blocked       BOOLEAN NOT NULL DEFAULT false,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- #12 ASM scan results
CREATE TABLE IF NOT EXISTS asm_findings (
  id            BIGSERIAL PRIMARY KEY,
  asset_kind    VARCHAR(50) NOT NULL,  -- 'subdomain','path','api','port'
  asset_value   TEXT NOT NULL,
  severity      VARCHAR(20) NOT NULL DEFAULT 'info',
  source        VARCHAR(50) NOT NULL DEFAULT 'manual',
  notes         TEXT,
  discovered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_asm_findings_kind_sev ON asm_findings (asset_kind, severity);
