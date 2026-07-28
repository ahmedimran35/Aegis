-- Canary tokens — invisible fields/URLs/cookies/headers that any
-- automated access reveals. Real deterministic recon signal.
CREATE TABLE IF NOT EXISTS canary_tokens (
  id            SERIAL PRIMARY KEY,
  name          TEXT NOT NULL,
  token_value   TEXT NOT NULL UNIQUE,
  kind          VARCHAR(20) NOT NULL CHECK (kind IN ('form_field','url','cookie','header')),
  placement     TEXT NOT NULL,
  enabled       BOOLEAN NOT NULL DEFAULT true,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_canary_token ON canary_tokens (token_value);
CREATE INDEX IF NOT EXISTS idx_canary_enabled ON canary_tokens (enabled) WHERE enabled = true;

CREATE TABLE IF NOT EXISTS canary_hits (
  id            SERIAL PRIMARY KEY,
  token_id      INT NOT NULL REFERENCES canary_tokens(id) ON DELETE CASCADE,
  ip            INET,
  method        VARCHAR(10),
  path          TEXT,
  user_agent    TEXT,
  matched_on    VARCHAR(40) NOT NULL,
  request_excerpt TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_canary_hits_token ON canary_hits (token_id, created_at DESC);
