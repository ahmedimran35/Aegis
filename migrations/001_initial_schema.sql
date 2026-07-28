CREATE TABLE IF NOT EXISTS rules (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    pattern TEXT NOT NULL,
    match_type VARCHAR(50) NOT NULL,
    action VARCHAR(20) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    priority INT DEFAULT 100,
    enabled BOOLEAN DEFAULT true,
    hit_count BIGINT DEFAULT 0,
    source VARCHAR(50) DEFAULT 'manual',
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS request_logs (
    id BIGSERIAL,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    client_ip INET NOT NULL,
    method VARCHAR(10) NOT NULL,
    host VARCHAR(255) NOT NULL,
    path TEXT NOT NULL,
    query TEXT,
    headers JSONB,
    body_hash VARCHAR(64),
    user_agent TEXT,
    action VARCHAR(20) NOT NULL,
    rule_id INT REFERENCES rules(id),
    threat_score FLOAT,
    ai_classification VARCHAR(50),
    response_code INT,
    response_time_ms INT,
    country VARCHAR(2),
    asn VARCHAR(50),
    bytes_sent BIGINT,
    bytes_received BIGINT
);

CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON request_logs (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_logs_client_ip ON request_logs (client_ip);
CREATE INDEX IF NOT EXISTS idx_logs_action ON request_logs (action);
CREATE INDEX IF NOT EXISTS idx_logs_threat ON request_logs (threat_score) WHERE threat_score > 0.7;

CREATE TABLE IF NOT EXISTS ai_decisions (
    id BIGSERIAL PRIMARY KEY,
    request_id BIGINT,
    model_name VARCHAR(100) NOT NULL,
    provider VARCHAR(20) NOT NULL,
    threat_score FLOAT NOT NULL,
    classification VARCHAR(50) NOT NULL,
    reasoning TEXT,
    latency_ms INT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS anomalies (
    id SERIAL PRIMARY KEY,
    type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    description TEXT NOT NULL,
    context JSONB,
    resolved BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    resolved_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS blocked_ips (
    id SERIAL PRIMARY KEY,
    ip_cidr CIDR NOT NULL,
    reason TEXT,
    source VARCHAR(50) DEFAULT 'manual',
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_blocked_ips_cidr ON blocked_ips USING GIST (ip_cidr);

CREATE TABLE IF NOT EXISTS ai_rule_suggestions (
    id SERIAL PRIMARY KEY,
    pattern TEXT NOT NULL,
    match_type VARCHAR(50) NOT NULL,
    suggested_action VARCHAR(20) NOT NULL,
    confidence FLOAT NOT NULL,
    sample_attacks JSONB,
    status VARCHAR(20) DEFAULT 'pending',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS config (
    key VARCHAR(255) PRIMARY KEY,
    value JSONB NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules (enabled) WHERE enabled = true;
