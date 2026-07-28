-- 022_ja4_support.up.sql
ALTER TABLE tls_fingerprints
  ADD COLUMN IF NOT EXISTS ja4_hash TEXT,
  ADD COLUMN IF NOT EXISTS ja4_h TEXT,
  ADD COLUMN IF NOT EXISTS proto TEXT NOT NULL DEFAULT 'tcp';

CREATE UNIQUE INDEX IF NOT EXISTS idx_tls_fp_ja4_unique
  ON tls_fingerprints (ja4_hash)
  WHERE ja4_hash IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_tls_fp_ja4_h
  ON tls_fingerprints (ja4_h)
  WHERE ja4_h IS NOT NULL;