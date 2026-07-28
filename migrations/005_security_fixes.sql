-- Security fixes migration

-- Add must_change_password flag for forced password change on first login
ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN DEFAULT false;

-- Add token_version for JWT token revocation on password change
ALTER TABLE users ADD COLUMN IF NOT EXISTS token_version INTEGER DEFAULT 0;

-- Flag ALL admin users for forced password change if not already flagged
UPDATE users SET must_change_password = true WHERE role = 'admin' AND (must_change_password IS NULL OR must_change_password = false);

-- Flag users with known weak default hash (password: "admin")
UPDATE users SET must_change_password = true WHERE password_hash = '$2b$12$eIHRwoLME1qfOX7yywwGF.bkZgq6/jAt59MWMNnVoIJcc3lRDA1XC';
