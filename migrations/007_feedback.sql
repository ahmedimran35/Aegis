-- False positive feedback system
CREATE TABLE IF NOT EXISTS false_positives (
    id BIGSERIAL PRIMARY KEY,
    log_id BIGINT NOT NULL,
    rule_id INT,
    reason TEXT NOT NULL DEFAULT '',
    reviewed_by INT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_fp_log_id ON false_positives(log_id);
CREATE INDEX IF NOT EXISTS idx_fp_rule_id ON false_positives(rule_id);

-- Add false_positive_count to rules for quick reference
ALTER TABLE rules ADD COLUMN IF NOT EXISTS false_positive_count INT DEFAULT 0;
