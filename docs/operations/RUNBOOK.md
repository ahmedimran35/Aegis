# Aegis WAF Ops Runbook

This runbook covers the most common production incidents and the on-call
playbook for resolving them. Each section includes the alert name, what
triggers it, how to investigate, and the canonical fix.

## Alert: AEGIS_AI_BUDGET_EXHAUSTED

**Trigger:** AI cost controller rejected >50 calls in 5 minutes for the same
caller (per-IP or per-user bucket).

**Investigate:**
1. Open `/api/v1/ai/status` (admin role) — review `top_users` field for
   which key is hot.
2. Check the AI router in-memory metrics (and the `ai_decisions` table) for
   recent calls from that key — usually a runaway retry loop or a single
   client making thousands of classification requests.
3. If the caller is benign (a known power user), raise `MaxTokensPerHour` in
   `/api/v1/settings`.
4. If the caller is malicious or unknown, add it to the IP blocklist via
   `/api/v1/blocked_ips` and the immediate issue stops.

**Fix at scale:** Adjust `cost.MaxTokensPerHour` and `cost.MaxCallsPerMin`
constants in `cmd/waf-engine/main.go` for permanent policy change.

## Alert: AEGIS_ANOMALY_DETECTOR_SILENT

**Trigger:** AnomalyDetector has not produced a report in >30 minutes.

**Investigate:**
1. Check the waf-engine logs for the in-process anomaly detector reporting
   "stats unavailable". The detector runs inside the engine process (no
   separate container).
2. This means Redis is down. AnomalyDetector fail-CLOSED on missing stats;
   it will resume automatically when Redis returns.
3. Verify Redis with `redis-cli ping`. If Redis is healthy, check the
   `aegis:ai:detect` permission bit and that the redis-pool has not exhausted.

**Fix:** Restart Redis (or restore from the latest RDB if the issue is corruption).

## Alert: AEGIS_REGEX_REJECTED

**Trigger:** Operator attempted to save a rule via UI/DSL/API and `HasReDoSRisk`
returned non-nil.

**Investigate:**
1. The pattern is potentially catastrophic-backtracking. Either:
   - Rewrite with a non-backtracking shape (anchor, possessive quantifier via
     `(?:...)`).
   - Use `(?i)` case-insensitive only when necessary.
   - Test with the `redos_test.go` corpus.
2. If the pattern is vendor-supplied (a CRS rule copy) and provably safe on
   the production corpus, escalate the rule through the `wafrules.ReviewRule`
   audit endpoint which bypasses the gate under admin approval.

## Alert: AEGIS_HONEYPOT_SPIKE

**Trigger:** Honeypot drip queue >500 active sessions.

**Investigate:**
1. This is a slow-burn scan, not a true flood. Do NOT block the source range
   without coordinate check — scanners often rotate IPs.
2. Check `/api/v1/honeypot/stats` for which path prefixes are being hit.
3. The auto-blacklist (1h TTL) will stop the worst offenders. If the attack
   persists across IP rotations, raise the blocklist TTL via config.

## Alert: AEGIS_PII_LEAK_SUSPECTED

**Trigger:** PII detector flagged an outbound AI request containing email,
SSN, or credit-card patterns.

**Investigate:**
1. The scrubber ran, so no PII actually left the host. The alert is for
   upstream visibility — typically a sign that:
   - A user is pasting sensitive data into AI chat
   - A log entry contains PII that needs redaction
2. The redactor replaces with `[REDACTED:type]` tokens before sending.
3. If you see repeated flags, audit the `ai_decisions` table for the
   offending user and consider training them or disabling their AI quota.

## Onboarding

New operators: read this runbook end-to-end, then shadow an on-call shift
for at least 14 days before taking primary. Key items to memorize:

- `/api/v1/ai/status` — AI spend telemetry and provider health
- `/api/v1/ai/eval/report` — quality metrics (accuracy, p95 latency)
- `/api/v1/ai/anomalies` — detector health and recent findings
- `/healthz`, `/readyz` — liveness, readiness

## Contact

- Primary on-call: aegis-oncall@yourcompany.example
- Escalation: SRE manager on PagerDuty
- Vendor: GitHub issues at the project repo for non-emergency requests
