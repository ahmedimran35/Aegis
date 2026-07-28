-- Add columns for FP/FN -> rule auto-create pipeline
ALTER TABLE false_positives ADD COLUMN IF NOT EXISTS auto_rule_id INTEGER;
ALTER TABLE false_positives ADD COLUMN IF NOT EXISTS path TEXT;
ALTER TABLE false_positives ADD COLUMN IF NOT EXISTS payload TEXT;

ALTER TABLE false_negatives ADD COLUMN IF NOT EXISTS auto_rule_id INTEGER;
ALTER TABLE false_negatives ADD COLUMN IF NOT EXISTS path TEXT;
ALTER TABLE false_negatives ADD COLUMN IF NOT EXISTS payload TEXT;
ALTER TABLE false_negatives ADD COLUMN IF NOT EXISTS reason TEXT;

CREATE INDEX IF NOT EXISTS idx_rules_source ON rules(source) WHERE source = 'auto-feedback';
