-- 023_rule_conflicts.up.sql
-- Backing table for the /rules/conflicts endpoint that was previously
-- crashing with "relation rule_conflicts does not exist". The handler
-- in internal/api/real_handlers.go already issues:
--   SELECT id, rule_a_id, rule_b_id, reason, severity, detected_at
--                       FROM rule_conflicts ...
--   UPDATE rule_conflicts SET resolved = true, ...
-- so the schema below is the minimum the handler expects.
CREATE TABLE IF NOT EXISTS rule_conflicts (
  id            SERIAL PRIMARY KEY,
  rule_a_id     INT NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
  rule_b_id     INT NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
  reason        TEXT NOT NULL,
  severity      VARCHAR(20) NOT NULL DEFAULT 'low',
  detected_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  resolved      BOOLEAN NOT NULL DEFAULT false,
  resolved_at   TIMESTAMPTZ,
  CHECK (rule_a_id <> rule_b_id)
);
CREATE INDEX IF NOT EXISTS idx_rule_conflicts_unresolved
  ON rule_conflicts (detected_at DESC)
  WHERE resolved = false;
