-- OWASP Core Rule Set (CRS) - Essential WAF Rules
-- Source: owasp-crs
-- These rules cover the most common attack patterns

-- ============================================================
-- SQL Injection (15 rules)
-- ============================================================
INSERT INTO rules (name, pattern, match_type, action, severity, priority, source, description) VALUES
('SQLi: UNION SELECT', 'union\s+(all\s+)?select', 'regex', 'block', 'critical', 10, 'owasp-crs', 'Detects UNION-based SQL injection attempts'),
('SQLi: OR 1=1', '(or|and)\s+1\s*=\s*1', 'regex', 'block', 'critical', 10, 'owasp-crs', 'Detects classic boolean-based SQL injection'),
('SQLi: OR true', '(or|and)\s+true', 'regex', 'block', 'critical', 10, 'owasp-crs', 'Detects boolean-based SQL injection with true keyword'),
('SQLi: DROP TABLE', 'drop\s+table', 'regex', 'block', 'critical', 10, 'owasp-crs', 'Detects DROP TABLE attempts'),
('SQLi: DROP DATABASE', 'drop\s+database', 'regex', 'block', 'critical', 10, 'owasp-crs', 'Detects DROP DATABASE attempts'),
('SQLi: SLEEP()', 'sleep\s*\(\s*\d+', 'regex', 'block', 'high', 15, 'owasp-crs', 'Detects time-based SQL injection via SLEEP()'),
('SQLi: BENCHMARK()', 'benchmark\s*\(\s*\d+', 'regex', 'block', 'high', 15, 'owasp-crs', 'Detects time-based SQL injection via BENCHMARK()'),
('SQLi: WAITFOR DELAY', 'waitfor\s+delay', 'regex', 'block', 'high', 15, 'owasp-crs', 'Detects time-based SQL injection via WAITFOR DELAY'),
('SQLi: information_schema', 'information_schema', 'regex', 'block', 'high', 15, 'owasp-crs', 'Detects information_schema enumeration'),
('SQLi: LOAD_FILE()', 'load_file\s*\(', 'regex', 'block', 'critical', 10, 'owasp-crs', 'Detects LOAD_FILE() for file reading'),
('SQLi: INTO OUTFILE', 'into\s+(out|dump)file', 'regex', 'block', 'critical', 10, 'owasp-crs', 'Detects INTO OUTFILE for file writing'),
('SQLi: EXEC/EXECUTE', 'exec\s*\(|execute\s*\(', 'regex', 'block', 'high', 15, 'owasp-crs', 'Detects EXEC/EXECUTE for stored procedure abuse'),
('SQLi: Comment injection', '(--|#|/\*)\s*$', 'regex', 'block', 'medium', 20, 'owasp-crs', 'Detects SQL comment-based injection'),
('SQLi: HAVING clause', 'having\s+\d+\s*=\s*\d+', 'regex', 'block', 'high', 15, 'owasp-crs', 'Detects HAVING clause error-based injection'),
('SQLi: CAST/CONVERT', '(cast|convert)\s*\(', 'regex', 'block', 'medium', 20, 'owasp-crs', 'Detects CAST/CONVERT error-based injection');

-- ============================================================
-- Cross-Site Scripting / XSS (10 rules)
-- ============================================================
INSERT INTO rules (name, pattern, match_type, action, severity, priority, source, description) VALUES
('XSS: Script tag', '<\s*script', 'regex', 'block', 'critical', 10, 'owasp-crs', 'Detects script tag injection'),
('XSS: onerror event', 'onerror\s*=', 'regex', 'block', 'critical', 10, 'owasp-crs', 'Detects onerror event handler injection'),
('XSS: onload event', 'onload\s*=', 'regex', 'block', 'high', 15, 'owasp-crs', 'Detects onload event handler injection'),
('XSS: onclick event', 'onclick\s*=', 'regex', 'block', 'high', 15, 'owasp-crs', 'Detects onclick event handler injection'),
('XSS: javascript: protocol', 'javascript\s*:', 'regex', 'block', 'critical', 10, 'owasp-crs', 'Detects javascript: URI protocol'),
('XSS: eval()', 'eval\s*\(', 'regex', 'block', 'high', 15, 'owasp-crs', 'Detects eval() function call'),
('XSS: document.cookie', 'document\.cookie', 'regex', 'block', 'high', 15, 'owasp-crs', 'Detects document.cookie access'),
('XSS: document.write', 'document\.write\s*\(', 'regex', 'block', 'high', 15, 'owasp-crs', 'Detects document.write() injection'),
('XSS: SVG onload', '<\s*svg[^>]*onload', 'regex', 'block', 'critical', 10, 'owasp-crs', 'Detects SVG onload injection'),
('XSS: img onerror', '<\s*img[^>]*onerror', 'regex', 'block', 'critical', 10, 'owasp-crs', 'Detects img onerror injection');

-- ============================================================
-- Remote Code Execution / RCE (10 rules)
-- ============================================================
INSERT INTO rules (name, pattern, match_type, action, severity, priority, source, description) VALUES
('RCE: Command chain ;', ';\s*(ls|cat|whoami|id|pwd|uname|ifconfig|netstat)', 'regex', 'block', 'critical', 10, 'owasp-crs', 'Detects command chaining via semicolon'),
('RCE: Pipe command', '\|\s*(ls|cat|whoami|id|pwd|uname|bash|sh|zsh)', 'regex', 'block', 'critical', 10, 'owasp-crs', 'Detects command execution via pipe'),
('RCE: Backtick execution', '`[^`]{2,}`', 'regex', 'block', 'high', 15, 'owasp-crs', 'Detects backtick command execution'),
('RCE: system()', 'system\s*\(', 'regex', 'block', 'critical', 10, 'owasp-crs', 'Detects system() function call'),
('RCE: exec()', 'exec\s*\(', 'regex', 'block', 'critical', 10, 'owasp-crs', 'Detects exec() function call'),
('RCE: passthru()', 'passthru\s*\(', 'regex', 'block', 'critical', 10, 'owasp-crs', 'Detects passthru() function call'),
('RCE: shell_exec()', 'shell_exec\s*\(', 'regex', 'block', 'critical', 10, 'owasp-crs', 'Detects shell_exec() function call'),
('RCE: /etc/passwd', '/etc/passwd', 'regex', 'block', 'critical', 10, 'owasp-crs', 'Detects /etc/passwd access attempt'),
('RCE: /etc/shadow', '/etc/shadow', 'regex', 'block', 'critical', 10, 'owasp-crs', 'Detects /etc/shadow access attempt'),
('RCE: /bin/sh', '/bin/(ba)?sh', 'regex', 'block', 'high', 15, 'owasp-crs', 'Detects direct shell invocation');

-- ============================================================
-- Path Traversal (5 rules)
-- ============================================================
INSERT INTO rules (name, pattern, match_type, action, severity, priority, source, description) VALUES
('Traversal: Dot-dot-slash', '\.\./', 'regex', 'block', 'high', 15, 'owasp-crs', 'Detects directory traversal via ../'),
('Traversal: Dot-dot-backslash', '\.\.\\\\', 'regex', 'block', 'high', 15, 'owasp-crs', 'Detects directory traversal via ..\\'),
('Traversal: URL encoded', '%2e%2e', 'regex', 'block', 'high', 15, 'owasp-crs', 'Detects URL-encoded directory traversal'),
('Traversal: Double encoded', '%252e%252e', 'regex', 'block', 'high', 15, 'owasp-crs', 'Detects double URL-encoded directory traversal'),
('Traversal: Null byte', '%00', 'regex', 'block', 'critical', 10, 'owasp-crs', 'Detects null byte injection');

-- ============================================================
-- Scanner / Attack Tool Detection (5 rules)
-- ============================================================
INSERT INTO rules (name, pattern, match_type, action, severity, priority, source, description) VALUES
('Scanner: Nikto', 'nikto', 'regex', 'block', 'high', 15, 'owasp-crs', 'Detects Nikto vulnerability scanner'),
('Scanner: SQLMap', 'sqlmap', 'regex', 'block', 'high', 15, 'owasp-crs', 'Detects SQLMap automated SQL injection tool'),
('Scanner: Nmap', 'nmap', 'regex', 'block', 'medium', 20, 'owasp-crs', 'Detects Nmap network scanner'),
('Scanner: Nessus', 'nessus', 'regex', 'block', 'medium', 20, 'owasp-crs', 'Detects Nessus vulnerability scanner'),
('Scanner: Burp Suite', 'burp', 'regex', 'block', 'high', 15, 'owasp-crs', 'Detects Burp Suite proxy/scanner');

-- ============================================================
-- Protocol Attacks (5 rules)
-- ============================================================
INSERT INTO rules (name, pattern, match_type, action, severity, priority, source, description) VALUES
('Protocol: Header injection CRLF', '\r\n', 'regex', 'block', 'high', 15, 'owasp-crs', 'Detects CRLF header injection'),
('Protocol: Host header attack', '^Host:\s*(localhost|127\.0\.0\.1|0\.0\.0\.0)', 'regex', 'block', 'medium', 20, 'owasp-crs', 'Detects suspicious Host header values'),
('Protocol: Request smuggling CL', 'Content-Length:\s*0\s*\r\n\s*Content-Length', 'regex', 'block', 'critical', 10, 'owasp-crs', 'Detects HTTP request smuggling via Content-Length'),
('Protocol: Request smuggling TE', 'Transfer-Encoding:\s*chunked.*Transfer-Encoding', 'regex', 'block', 'critical', 10, 'owasp-crs', 'Detects HTTP request smuggling via Transfer-Encoding'),
('Protocol: TRACE method', '^TRACE\s', 'regex', 'block', 'medium', 20, 'owasp-crs', 'Detects TRACE method which can expose headers');
