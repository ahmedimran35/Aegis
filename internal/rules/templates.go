package rules

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TemplateRule is a rule within a protection template.
type TemplateRule struct {
	Name          string
	Pattern       string
	MatchType     string
	Action        string
	Severity      string
	Priority      int
	ParanoiaLevel int
	Description   string
}

// ProtectionTemplate defines a preset security profile.
type ProtectionTemplate struct {
	ID            string
	Name          string
	Description   string
	ParanoiaLevel int
	Rules         []TemplateRule
}

var templates = []ProtectionTemplate{
	{
		ID:            "api-protection",
		Name:          "API Protection",
		Description:   "Protect REST/GraphQL APIs from injection, abuse, and enumeration attacks",
		ParanoiaLevel: 2,
		Rules: []TemplateRule{
			{Name: "api-sqli-json", Pattern: `(?i)(union\s+select|or\s+1\s*=\s*1|'\s*or\s*'|--\s*$|;\s*drop\s+table)`, MatchType: "regex", Action: "block", Severity: "critical", Priority: 10, ParanoiaLevel: 1, Description: "SQL injection in JSON request bodies"},
			{Name: "api-path-traversal", Pattern: `(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/)`, MatchType: "regex", Action: "block", Severity: "high", Priority: 10, ParanoiaLevel: 1, Description: "Path traversal in URL paths"},
			{Name: "api-ssrf-patterns", Pattern: `(?i)(169\.254\.169\.254|metadata\.google|localhost|127\.0\.0\.1|0\.0\.0\.0)`, MatchType: "regex", Action: "block", Severity: "high", Priority: 10, ParanoiaLevel: 1, Description: "Server-side request forgery patterns"},
			{Name: "api-method-enforcement", Pattern: `^(GET|POST|PUT|DELETE|PATCH|OPTIONS)$`, MatchType: "regex", Action: "log", Severity: "medium", Priority: 50, ParanoiaLevel: 2, Description: "HTTP method enforcement for APIs"},
			{Name: "api-oversized-body", Pattern: `Content-Length:\s*\d{8,}`, MatchType: "regex", Action: "log", Severity: "medium", Priority: 50, ParanoiaLevel: 2, Description: "Oversized request body detection"},
			{Name: "api-graphql-injection", Pattern: `(?i)(__schema|__type|mutation\s*\{|query\s*\{.*\{.*\{)`, MatchType: "regex", Action: "log", Severity: "medium", Priority: 30, ParanoiaLevel: 2, Description: "GraphQL introspection and deep query detection"},
			{Name: "api-jwt-manipulation", Pattern: `(?i)(eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*alg.*none)`, MatchType: "regex", Action: "block", Severity: "critical", Priority: 5, ParanoiaLevel: 1, Description: "JWT algorithm=none attack"},
			{Name: "api-xml-xxe", Pattern: `(?i)(<!DOCTYPE|<!ENTITY|SYSTEM\s+['\"]file:)`, MatchType: "regex", Action: "block", Severity: "critical", Priority: 5, ParanoiaLevel: 1, Description: "XML external entity injection"},
		},
	},
	{
		ID:            "web-app",
		Name:          "Web Application Protection",
		Description:   "Standard protection for web applications against OWASP Top 10",
		ParanoiaLevel: 1,
		Rules: []TemplateRule{
			{Name: "web-xss-script", Pattern: `(?i)<\s*script[\s>]`, MatchType: "regex", Action: "block", Severity: "critical", Priority: 5, ParanoiaLevel: 1, Description: "XSS via script tags"},
			{Name: "web-xss-event", Pattern: `(?i)(on\w+\s*=|javascript\s*:|vbscript\s*:)`, MatchType: "regex", Action: "block", Severity: "high", Priority: 10, ParanoiaLevel: 1, Description: "XSS via event handlers"},
			{Name: "web-sqli-select", Pattern: `(?i)(union\s+select|select\s+.*\s+from\s+|insert\s+into|delete\s+from|drop\s+table|update\s+.*\s+set\s+)`, MatchType: "regex", Action: "block", Severity: "critical", Priority: 5, ParanoiaLevel: 1, Description: "SQL injection via SQL keywords"},
			{Name: "web-sqli-comments", Pattern: `(?i)(/\*.*\*/|--\s+[^\n]*|;\s*--)`, MatchType: "regex", Action: "block", Severity: "high", Priority: 10, ParanoiaLevel: 1, Description: "SQL injection via comments"},
			{Name: "web-lfi-traversal", Pattern: `(\.\./|\.\.\\|%2e%2e%2f|%2e%2e%5c|/etc/passwd|/proc/self)`, MatchType: "regex", Action: "block", Severity: "critical", Priority: 5, ParanoiaLevel: 1, Description: "Local file inclusion via path traversal"},
			{Name: "web-rfi-remote", Pattern: `(?i)(https?://|ftp://|php://|data://|expect://|input://).*\.(php|asp|jsp|exe)`, MatchType: "regex", Action: "block", Severity: "critical", Priority: 5, ParanoiaLevel: 1, Description: "Remote file inclusion"},
			{Name: "web-rce-shell", Pattern: `(?i)(;\s*(ls|cat|whoami|id|uname|ifconfig|netstat|wget|curl)\b|\|\s*(ls|cat|whoami|id))`, MatchType: "regex", Action: "block", Severity: "critical", Priority: 5, ParanoiaLevel: 1, Description: "Remote command execution via shell commands"},
			{Name: "web-code-inject-funcs", Pattern: `(?i)(assert\s*\(|preg_replace\s*\(.*/e|system\s*\(|exec\s*\(|passthru\s*\(|shell_exec\s*\()`, MatchType: "regex", Action: "block", Severity: "critical", Priority: 5, ParanoiaLevel: 1, Description: "PHP code injection via dangerous functions"},
			{Name: "web-asp-injection", Pattern: `(?i)(execute\s*\(|createobject|wscript\.shell|cmd\.exe)`, MatchType: "regex", Action: "block", Severity: "critical", Priority: 5, ParanoiaLevel: 1, Description: "ASP code injection"},
			{Name: "web-directory-listing", Pattern: `(?i)(Index of /|Directory listing for|<pre>\s*<h1>Directory)`, MatchType: "regex", Action: "log", Severity: "medium", Priority: 50, ParanoiaLevel: 1, Description: "Directory listing disclosure"},
			{Name: "web-scanner-ua", Pattern: `(?i)(nikto|sqlmap|nmap|nessus|burp|dirbuster|gobuster|wfuzz|hydra|acunetix|masscan)`, MatchType: "regex", Action: "block", Severity: "high", Priority: 20, ParanoiaLevel: 1, Description: "Known vulnerability scanner user agents"},
			{Name: "web-ssti-template", Pattern: `(?i)(\{\{.*\}\}|\{%.*%\}|\$\{.*\}|<#.*#>)`, MatchType: "regex", Action: "log", Severity: "high", Priority: 20, ParanoiaLevel: 1, Description: "Server-side template injection patterns"},
		},
	},
	{
		ID:            "high-security",
		Name:          "High Security",
		Description:   "Maximum protection with tighter rules — may have more false positives",
		ParanoiaLevel: 3,
		Rules: []TemplateRule{
			// Include all web-app rules at PL1
			{Name: "hs-xss-script", Pattern: `(?i)<\s*script[\s>]`, MatchType: "regex", Action: "block", Severity: "critical", Priority: 5, ParanoiaLevel: 1, Description: "XSS via script tags"},
			{Name: "hs-sqli-keywords", Pattern: `(?i)(union\s+select|select\s+.*\s+from\s+|insert\s+into|delete\s+from|drop\s+table)`, MatchType: "regex", Action: "block", Severity: "critical", Priority: 5, ParanoiaLevel: 1, Description: "SQL injection keywords"},
			{Name: "hs-rce-shell", Pattern: `(?i)(;\s*(ls|cat|whoami|id|uname|ifconfig|netstat|wget|curl)\b)`, MatchType: "regex", Action: "block", Severity: "critical", Priority: 5, ParanoiaLevel: 1, Description: "Remote command execution"},
			// Additional high-security rules at PL2+
			{Name: "hs-crlf-injection", Pattern: `(%0d%0a|%0D%0A|\r\n)`, MatchType: "regex", Action: "block", Severity: "high", Priority: 10, ParanoiaLevel: 2, Description: "CRLF header injection"},
			{Name: "hs-unicode-bypass", Pattern: `(%u[0-9a-fA-F]{4}|\\u[0-9a-fA-F]{4}|%c0%af|%c1%9c)`, MatchType: "regex", Action: "log", Severity: "high", Priority: 20, ParanoiaLevel: 2, Description: "Unicode normalization bypass attempts"},
			{Name: "hs-encoded-payloads", Pattern: `(%3[cC]|%3[eE]|%22|%27|%3[bB]|%00)`, MatchType: "regex", Action: "log", Severity: "medium", Priority: 30, ParanoiaLevel: 2, Description: "URL-encoded attack payloads"},
			{Name: "hs-cookie-injection", Pattern: `(?i)(document\.cookie|cookie\s*:\s*|set-cookie:)`, MatchType: "regex", Action: "block", Severity: "high", Priority: 10, ParanoiaLevel: 2, Description: "Cookie injection attacks"},
			{Name: "hs-header-injection", Pattern: `(?i)(host:\s*[^\r\n]*\s+|referer:\s*[^\r\n]*\s+)`, MatchType: "regex", Action: "log", Severity: "medium", Priority: 30, ParanoiaLevel: 3, Description: "HTTP header injection"},
			{Name: "hs-null-byte", Pattern: `(%00|\\x00|\\0)`, MatchType: "regex", Action: "block", Severity: "high", Priority: 10, ParanoiaLevel: 2, Description: "Null byte injection"},
			{Name: "hs-prototype-pollution", Pattern: `(?i)(__proto__|constructor\[|prototype\[)`, MatchType: "regex", Action: "block", Severity: "high", Priority: 10, ParanoiaLevel: 2, Description: "JavaScript prototype pollution"},
			{Name: "hs-nosql-injection", Pattern: `(?i)(\$gt|\$ne|\$lt|\$regex|\$where|\$exists|\$or|\$and)`, MatchType: "regex", Action: "log", Severity: "medium", Priority: 30, ParanoiaLevel: 3, Description: "NoSQL injection operators"},
			{Name: "hs-ldap-injection", Pattern: `(\)\(|\*\)|\(\||&\(|\|\()`, MatchType: "regex", Action: "log", Severity: "medium", Priority: 30, ParanoiaLevel: 3, Description: "LDAP injection patterns"},
		},
	},
	{
		ID:            "low-false-positives",
		Name:          "Low False Positives",
		Description:   "Conservative rules that only catch obvious attacks — minimal false positives",
		ParanoiaLevel: 1,
		Rules: []TemplateRule{
			{Name: "lfp-obvious-sqli", Pattern: `(?i)(union\s+select\s+|'\s+or\s+'\d+'\s*=\s*'\d+'|;\s*drop\s+table\s+|'\s*;\s*--)`, MatchType: "regex", Action: "block", Severity: "critical", Priority: 5, ParanoiaLevel: 1, Description: "Obvious SQL injection patterns only"},
			{Name: "lfp-script-tag", Pattern: `(?i)<\s*script\s*>`, MatchType: "regex", Action: "block", Severity: "critical", Priority: 5, ParanoiaLevel: 1, Description: "Obvious XSS script tags"},
			{Name: "lfp-etc-passwd", Pattern: `/etc/passwd`, MatchType: "string", Action: "block", Severity: "critical", Priority: 5, ParanoiaLevel: 1, Description: "Linux passwd file access"},
			{Name: "lfp-cmd-exe", Pattern: `cmd\.exe`, MatchType: "string", Action: "block", Severity: "critical", Priority: 5, ParanoiaLevel: 1, Description: "Windows command execution"},
			{Name: "lfp-scanner-tools", Pattern: `(?i)(nikto|sqlmap|nmap|nessus|burpsuite|acunetix)`, MatchType: "regex", Action: "block", Severity: "high", Priority: 20, ParanoiaLevel: 1, Description: "Known attack tool user agents"},
			{Name: "lfp-path-traversal", Pattern: `../../../`, MatchType: "string", Action: "block", Severity: "high", Priority: 10, ParanoiaLevel: 1, Description: "Obvious path traversal"},
			{Name: "lfp-base64-decode-func", Pattern: `base64_decode\s*\(`, MatchType: "regex", Action: "block", Severity: "critical", Priority: 5, ParanoiaLevel: 1, Description: "PHP base64 decode (web shell indicator)"},
			{Name: "lfp-log4shell", Pattern: `\$\{jndi:(ldap|ldaps|rmi|dns|iiop|corba|nds|http)://`, MatchType: "regex", Action: "block", Severity: "critical", Priority: 1, ParanoiaLevel: 1, Description: "Log4Shell JNDI injection (CVE-2021-44228)"},
		},
	},
	{
		// crs-pl2 — built dynamically from CuratedCRSPack. 24 rules covering
		// SQLi, XSS, RFI/LFI, command injection, PHP injection, XXE, traversal,
		// header smuggling, null-byte. ReDoS-safe; full ReDoS-gate enforcement
		// lives in the CuratedCRSPack itself (see crs_pack.go).
		ID:            "crs-pl2",
		Name:          "OWASP CRS Paranoia Level 2 (curated)",
		Description:   "Curated OWASP CRS-PL2 rule set covering the highest-signal vectors (SQLi, XSS, RFI/LFI, command injection, XXE, traversal, header smuggling). All patterns pre-checked for ReDoS.",
		ParanoiaLevel: 2,
		Rules:         curatedCRSToTemplateRules(),
	},
}

// GetTemplates returns all available protection templates.
func GetTemplates() []ProtectionTemplate {
	return templates
}

// curatedCRSToTemplateRules converts CuratedCRSPack into TemplateRule
// entries. ReDoS-gated — packs that contain unsafe patterns return an empty
// slice for that rule (defensive; curation ensures none today).
func curatedCRSToTemplateRules() []TemplateRule {
	out := make([]TemplateRule, 0, len(CuratedCRSPack))
	for _, c := range CuratedCRSPack {
		if err := HasReDoSRisk(c.Pattern); err != nil {
			continue
		}
		matchType := "regex"
		if c.Operator == "contains" {
			matchType = "string"
		}
		priority := 5
		switch c.Severity {
		case "CRITICAL":
			priority = 1
		case "HIGH":
			priority = 5
		case "MEDIUM":
			priority = 10
		case "LOW":
			priority = 20
		}
		name := fmt.Sprintf("crs-%d", c.ID)
		if c.Operator == "ip" {
			// ip match needs IP converted to a CIDR check via matchType=cidr;
			// downstream engine falls back to string match if cidr unsupported.
			matchType = "string"
		}
		if c.Operator == "gt" || c.Operator == "lt" {
			matchType = "gt"
			if c.Operator == "lt" {
				matchType = "lt"
			}
		}
		out = append(out, TemplateRule{
			Name:          name,
			Pattern:       c.Pattern,
			MatchType:     matchType,
			Action:        c.Action,
			Severity:      c.Severity,
			Priority:      priority,
			ParanoiaLevel: 2,
			Description:   c.Msg,
		})
	}
	return out
}

// GetTemplate returns a template by ID.
func GetTemplate(id string) *ProtectionTemplate {
	for _, t := range templates {
		if t.ID == id {
			return &t
		}
	}
	return nil
}

// ApplyTemplate applies a template to the database (inserts rules).
// Returns the number of rules inserted.
func ApplyTemplate(ctx context.Context, pool *pgxpool.Pool, templateID string) (int, error) {
	tmpl := GetTemplate(templateID)
	if tmpl == nil {
		return 0, fmt.Errorf("template %q not found", templateID)
	}

	count := 0
	for _, r := range tmpl.Rules {
		_, err := pool.Exec(ctx,
			`INSERT INTO rules (name, pattern, match_type, action, severity, priority, source, description, paranoia_level, enabled)
			 VALUES ($1, $2, $3, $4, $5, $6, 'template', $7, $8, true)
			 ON CONFLICT (name) DO NOTHING`,
			r.Name, r.Pattern, r.MatchType, r.Action, r.Severity, r.Priority, r.Description, r.ParanoiaLevel)
		if err != nil {
			return count, fmt.Errorf("insert rule %q: %w", r.Name, err)
		}
		count++
	}

	return count, nil
}
