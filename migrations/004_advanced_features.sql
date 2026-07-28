-- RBAC: Extend users table with more roles
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('admin', 'editor', 'analyst', 'viewer'));

-- Audit log: who changed what when
CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id),
    username VARCHAR(100),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id VARCHAR(100),
    details JSONB,
    ip_address INET,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_audit_log_created ON audit_log (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_user ON audit_log (user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_resource ON audit_log (resource_type, resource_id);

-- Sessions: cookie-based session tracking
CREATE TABLE IF NOT EXISTS sessions (
    id VARCHAR(64) PRIMARY KEY,
    client_ip INET NOT NULL,
    user_agent TEXT,
    fingerprint VARCHAR(64),
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    request_count INT DEFAULT 1,
    blocked_count INT DEFAULT 0,
    country VARCHAR(2),
    metadata JSONB
);
CREATE INDEX IF NOT EXISTS idx_sessions_ip ON sessions (client_ip);
CREATE INDEX IF NOT EXISTS idx_sessions_fingerprint ON sessions (fingerprint) WHERE fingerprint IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_sessions_last_seen ON sessions (last_seen DESC);

-- GeoIP: cached country blocks
CREATE TABLE IF NOT EXISTS geoip_rules (
    id SERIAL PRIMARY KEY,
    country_code VARCHAR(2) NOT NULL,
    action VARCHAR(20) NOT NULL DEFAULT 'block',
    reason TEXT,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_geoip_rules_country ON geoip_rules (country_code);

-- Allowlist mode: explicit allow rules
CREATE TABLE IF NOT EXISTS allowlist_rules (
    id SERIAL PRIMARY KEY,
    rule_type VARCHAR(50) NOT NULL,
    pattern TEXT NOT NULL,
    description TEXT,
    priority INT DEFAULT 100,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_allowlist_enabled ON allowlist_rules (enabled) WHERE enabled = true;

-- Virtual patching: CVE-specific rules
CREATE TABLE IF NOT EXISTS virtual_patches (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(20) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    rule_pattern TEXT NOT NULL,
    match_type VARCHAR(50) NOT NULL DEFAULT 'regex',
    action VARCHAR(20) NOT NULL DEFAULT 'block',
    severity VARCHAR(20) NOT NULL DEFAULT 'high',
    affected_paths TEXT[],
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_virtual_patches_cve ON virtual_patches (cve_id);

-- API schema validation: OpenAPI specs
CREATE TABLE IF NOT EXISTS api_schemas (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    base_path VARCHAR(500) NOT NULL,
    spec JSONB NOT NULL,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Request replay: stored blocked requests
CREATE TABLE IF NOT EXISTS request_replay (
    id BIGSERIAL PRIMARY KEY,
    original_log_id BIGINT,
    client_ip INET,
    method VARCHAR(10) NOT NULL,
    host VARCHAR(255) NOT NULL,
    path TEXT NOT NULL,
    query TEXT,
    headers JSONB,
    body TEXT,
    action VARCHAR(20),
    rule_id INT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_replay_created ON request_replay (created_at DESC);

-- Rule testing: test results
CREATE TABLE IF NOT EXISTS rule_tests (
    id SERIAL PRIMARY KEY,
    rule_id INT,
    test_request JSONB NOT NULL,
    result JSONB,
    passed BOOLEAN,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- TLS fingerprinting: JA3/JA4 hashes
CREATE TABLE IF NOT EXISTS tls_fingerprints (
    id SERIAL PRIMARY KEY,
    ja3_hash VARCHAR(32) NOT NULL,
    ja3_full TEXT,
    client_ip INET,
    user_agent TEXT,
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    request_count INT DEFAULT 1,
    reputation VARCHAR(20) DEFAULT 'unknown',
    notes TEXT
);
CREATE INDEX IF NOT EXISTS idx_tls_ja3 ON tls_fingerprints (ja3_hash);
CREATE UNIQUE INDEX IF NOT EXISTS idx_tls_ja3_unique ON tls_fingerprints (ja3_hash);

-- Honeypot: decoy endpoint hits
CREATE TABLE IF NOT EXISTS honeypot_hits (
    id BIGSERIAL PRIMARY KEY,
    client_ip INET NOT NULL,
    method VARCHAR(10) NOT NULL,
    path TEXT NOT NULL,
    query TEXT,
    headers JSONB,
    body TEXT,
    user_agent TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_honeypot_ip ON honeypot_hits (client_ip);
CREATE INDEX IF NOT EXISTS idx_honeypot_created ON honeypot_hits (created_at DESC);

-- SIEM export config
CREATE TABLE IF NOT EXISTS siem_config (
    id SERIAL PRIMARY KEY,
    export_type VARCHAR(50) NOT NULL,
    endpoint TEXT,
    format VARCHAR(20) DEFAULT 'json',
    enabled BOOLEAN DEFAULT true,
    last_export_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Connection tracking for DDoS protection
CREATE TABLE IF NOT EXISTS connection_limits (
    id SERIAL PRIMARY KEY,
    limit_type VARCHAR(50) NOT NULL,
    max_value INT NOT NULL,
    window_seconds INT NOT NULL,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Insert default connection limits
INSERT INTO connection_limits (limit_type, max_value, window_seconds) VALUES
    ('max_concurrent_connections', 1000, 0),
    ('max_connections_per_ip', 50, 0),
    ('max_new_connections_per_second', 100, 1),
    ('max_requests_per_connection', 1000, 0)
ON CONFLICT DO NOTHING;
