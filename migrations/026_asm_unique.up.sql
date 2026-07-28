-- The original 025_features.up.sql created asm_findings but forgot
-- the unique constraint that PathClassifier's ON CONFLICT clause
-- depends on. Without this, every 4xx request from the classifier
-- returns a 500 (constraint matching error) and the row is never
-- written. Adding the unique index now.
CREATE UNIQUE INDEX IF NOT EXISTS idx_asm_findings_kind_value
  ON asm_findings (asset_kind, asset_value);
