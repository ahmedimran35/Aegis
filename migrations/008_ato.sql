-- Account Takeover (ATO) detection events
CREATE TABLE IF NOT EXISTS ato_events (
    id BIGSERIAL PRIMARY KEY,
    ip INET NOT NULL,
    username TEXT NOT NULL DEFAULT '',
    attack_type TEXT NOT NULL,          -- credential_stuffing, brute_force, distributed, spray
    attempt_count INT NOT NULL DEFAULT 0,
    unique_usernames INT NOT NULL DEFAULT 0,
    unique_ips INT NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ato_events_ip ON ato_events(ip);
CREATE INDEX IF NOT EXISTS idx_ato_events_created ON ato_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ato_events_type ON ato_events(attack_type);
