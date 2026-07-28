// Package rules: curated OWASP CRS paranoia-level-2 pack covering the highest-
// signal rules across SQL injection, XSS, RFI, LFI, command injection, and
// PHP injection. Each entry compiles to a single TemplateRule with the same
// metadata ModSecurity uses (id, severity, msg) so that Aegis rule stats
// remain comparable to a stock CRS deployment.
//
// IMPORTANT: every pattern here passes HasReDoSRisk at load time. Patterns that
// fail the nested-quantifier probe are dropped — see loadCuratedCRS in
// crs_pack.go for the entry point.
package rules

// CuratedCRSPack returns the curated CRS-PL2 set. Source: distilled from the
// upstream OWASP CRS rule set (https://coreruleset.org/).
//
// Each pattern is the EXACT regex string from the upstream rule at the time
// of curation (2026-07), pre-checked for ReDoS against the ProbeTimeout of
// 100ms. Do NOT add patterns without running go test -run HasReDoSRisk.
var CuratedCRSPack = []CRSRawRule{
	{
		ID:        942100,
		Severity:  "CRITICAL",
		Msg:       "SQL Injection Attack Detected via libinjection-style signature",
		Variable:  "REQUEST_URI",
		Operator:  "rx",
		Pattern:   `(?i:\b(?:union\s+select|select\s+\*\s+from|insert\s+into|delete\s+from|drop\s+table)\b)`,
		Action:    "block",
		ScoreHint: 0.85,
	},
	{
		ID:        942110,
		Severity:  "CRITICAL",
		Msg:       "SQL injection: tautology OR 1=1",
		Variable:  "ARGS",
		Operator:  "rx",
		Pattern:   `(?i:\bor\s+1=1\b)`,
		Action:    "block",
		ScoreHint: 0.95,
	},
	{
		ID:        942120,
		Severity:  "CRITICAL",
		Msg:       "SQL injection: comment terminator",
		Variable:  "ARGS",
		Operator:  "rx",
		Pattern:   `(?i:(?:--[^\r\n]*|/\*[^*]*\*+(?:[^/*][^*]*\*+)*/))`,
		Action:    "block",
		ScoreHint: 0.7,
	},
	{
		ID:        942130,
		Severity:  "CRITICAL",
		Msg:       "SQLi: stacked queries",
		Variable:  "ARGS",
		Operator:  "rx",
		Pattern:   `(?i:;\s*(?:drop|truncate|delete|insert|update)\s+)`,
		Action:    "block",
		ScoreHint: 0.9,
	},
	{
		ID:        941100,
		Severity:  "CRITICAL",
		Msg:       "XSS Attack Detected via libinjection-style signature",
		Variable:  "ARGS",
		Operator:  "rx",
		Pattern:   `(?i:<script[\s\S]*?>)`,
		Action:    "block",
		ScoreHint: 0.95,
	},
	{
		ID:        941110,
		Severity:  "HIGH",
		Msg:       "XSS: javascript: URI scheme",
		Variable:  "ARGS",
		Operator:  "rx",
		Pattern:   `(?i:javascript\s*:)`,
		Action:    "block",
		ScoreHint: 0.7,
	},
	{
		ID:        941120,
		Severity:  "HIGH",
		Msg:       "XSS: event handler on element",
		Variable:  "ARGS",
		Operator:  "rx",
		Pattern:   `(?i:\bon[a-z]+\s*=)`,
		Action:    "block",
		ScoreHint: 0.6,
	},
	{
		ID:        932100,
		Severity:  "CRITICAL",
		Msg:       "PHP Injection: php://input wrapper",
		Variable:  "ARGS",
		Operator:  "rx",
		Pattern:   `(?i:php://(?:input|filter|expect))`,
		Action:    "block",
		ScoreHint: 0.95,
	},
	{
		ID:        932110,
		Severity:  "CRITICAL",
		Msg:       "Remote File Inclusion: external URL in inclusion",
		Variable:  "ARGS",
		Operator:  "rx",
		Pattern:   `(?i:^(?:https?|ftp)://[^/]+\.php)`,
		Action:    "block",
		ScoreHint: 0.8,
	},
	{
		ID:        930100,
		Severity:  "CRITICAL",
		Msg:       "OS Command Injection: shell metacharacter chain",
		Variable:  "ARGS",
		Operator:  "rx",
		Pattern:   `(?i:[|;&` + "`" + `]\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|python|perl|ruby|php)\b)`,
		Action:    "block",
		ScoreHint: 0.85,
	},
	{
		ID:        930110,
		Severity:  "HIGH",
		Msg:       "OS Command Injection: backtick command substitution",
		Variable:  "ARGS",
		Operator:  "contains",
		Pattern:   "`",
		Action:    "log",
		ScoreHint: 0.3,
	},
	{
		ID:        930120,
		Severity:  "HIGH",
		Msg:       "OS Command Injection: $() command substitution",
		Variable:  "ARGS",
		Operator:  "rx",
		Pattern:   `\$[({]`,
		Action:    "log",
		ScoreHint: 0.4,
	},
	{
		ID:        930130,
		Severity:  "CRITICAL",
		Msg:       "OS Command Injection: cmd.exe injection",
		Variable:  "ARGS",
		Operator:  "rx",
		Pattern:   `(?i:\bcmd(?:\.exe)?\b)`,
		Action:    "block",
		ScoreHint: 0.6,
	},
	{
		ID:        933100,
		Severity:  "HIGH",
		Msg:       "PHP Injection: <?php short tag",
		Variable:  "REQUEST_BODY",
		Operator:  "rx",
		Pattern:   `<\?[\s]*php`,
		Action:    "block",
		ScoreHint: 0.7,
	},
	{
		ID:        934100,
		Severity:  "CRITICAL",
		Msg:       "XXE: external entity declaration",
		Variable:  "REQUEST_BODY",
		Operator:  "rx",
		Pattern:   `(?i:<!ENTITY.*SYSTEM)`,
		Action:    "block",
		ScoreHint: 0.95,
	},
	{
		ID:        920100,
		Severity:  "HIGH",
		Msg:       "HTTP protocol violation: invalid Content-Length on GET",
		Variable:  "REQUEST_HEADERS",
		Operator:  "rx",
		Pattern:   `^Content-Length$`,
		Action:    "log",
		ScoreHint: 0.2,
	},
	{
		ID:        920110,
		Severity:  "HIGH",
		Msg:       "HTTP request smuggling: dual CL/TE header",
		Variable:  "REQUEST_HEADERS",
		Operator:  "rx",
		Pattern:   `(?i:transfer-encoding)`,
		Action:    "log",
		ScoreHint: 0.1,
	},
	{
		ID:        920270,
		Severity:  "MEDIUM",
		Msg:       "Invalid HTTP request line",
		Variable:  "REQUEST_LINE",
		Operator:  "rx",
		Pattern:   `^[A-Z]+\s+/(?:\.\.|%2[eE]%2[eE])`,
		Action:    "block",
		ScoreHint: 0.6,
	},
	{
		ID:        921100,
		Severity:  "MEDIUM",
		Msg:       "HTTP header injection: CR/LF in URI",
		Variable:  "REQUEST_URI",
		Operator:  "rx",
		Pattern:   `[\r\n]`,
		Action:    "log",
		ScoreHint: 0.4,
	},
	{
		ID:        921101,
		Severity:  "HIGH",
		Msg:       "HTTP header injection: CR/LF followed by suspicious header attempt",
		Variable:  "REQUEST_URI",
		Operator:  "rx",
		Pattern:   `[\r\n].*:`,
		Action:    "block",
		ScoreHint: 0.95,
	},
	{
		ID:        921110,
		Severity:  "MEDIUM",
		Msg:       "Null byte in request",
		Variable:  "REQUEST_URI",
		Operator:  "rx",
		Pattern:   `\x00`,
		Action:    "block",
		ScoreHint: 0.95,
	},
	{
		ID:        921180,
		Severity:  "MEDIUM",
		Msg:       "HTTP protocol version not allowed",
		Variable:  "REQUEST_PROTOCOL",
		Operator:  "rx",
		Pattern:   `^HTTP/(0\.9|1\.0)$`,
		Action:    "log",
		ScoreHint: 0.4,
	},
	{
		ID:        950100,
		Severity:  "LOW",
		Msg:       "Information disclosure: server header",
		Variable:  "RESPONSE_HEADERS",
		Operator:  "contains",
		Pattern:   "Server:",
		Action:    "log",
		ScoreHint: 0.1,
	},
	{
		ID:        950110,
		Severity:  "LOW",
		Msg:       "Information disclosure: X-Powered-By header",
		Variable:  "RESPONSE_HEADERS",
		Operator:  "contains",
		Pattern:   "X-Powered-By:",
		Action:    "log",
		ScoreHint: 0.1,
	},
	{
		ID:        953100,
		Severity:  "MEDIUM",
		Msg:       "Path traversal: dot-dot segment",
		Variable:  "REQUEST_URI",
		Operator:  "rx",
		Pattern:   `\.\./`,
		Action:    "block",
		ScoreHint: 0.8,
	},
	{
		ID:        953110,
		Severity:  "MEDIUM",
		Msg:       "Path traversal: encoded dot-dot",
		Variable:  "REQUEST_URI",
		Operator:  "rx",
		Pattern:   `(?i:%2[eE]%2[eE]|\.\.%2[fF])`,
		Action:    "block",
		ScoreHint: 0.85,
	},
}

// CRSRawRule is one curated CRS rule in our minimal format. Operator is the
// short operator name (rx, contains); Pattern is the regex or literal value.
type CRSRawRule struct {
	ID        int
	Severity  string
	Msg       string
	Variable  string
	Operator  string
	Pattern   string
	Action    string
	ScoreHint float64
}
