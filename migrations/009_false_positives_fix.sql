CREATE TABLE IF NOT EXISTS false_positives (
  id BIGSERIAL PRIMARY KEY,
  log_id BIGINT REFERENCES request_logs(id),
  rule_id INT,
  reason TEXT,
  reviewed_by INT,
  username TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_fp_rule ON false_positives(rule_id);
CREATE INDEX IF NOT EXISTS idx_fp_log ON false_positives(log_id);
