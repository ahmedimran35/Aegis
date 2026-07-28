-- Anomaly scoring: add paranoia level and transforms to rules
ALTER TABLE rules ADD COLUMN IF NOT EXISTS paranoia_level INT DEFAULT 1;
ALTER TABLE rules ADD COLUMN IF NOT EXISTS transforms TEXT DEFAULT '';

-- Update existing rules with sensible paranoia levels based on severity
UPDATE rules SET paranoia_level = 1 WHERE severity IN ('critical', 'high') AND paranoia_level = 1;
UPDATE rules SET paranoia_level = 2 WHERE severity = 'medium' AND paranoia_level = 1;
UPDATE rules SET paranoia_level = 3 WHERE severity = 'low' AND paranoia_level = 1;
