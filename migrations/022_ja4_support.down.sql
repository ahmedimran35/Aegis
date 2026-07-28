-- 022_ja4_support.down.sql
DROP INDEX IF EXISTS idx_tls_fp_ja4_h;
DROP INDEX IF EXISTS idx_tls_fp_ja4_unique;
ALTER TABLE tls_fingerprints
  DROP COLUMN IF EXISTS proto,
  DROP COLUMN IF EXISTS ja4_h,
  DROP COLUMN IF EXISTS ja4_hash;