package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/redis/go-redis/v9"
	"github.com/user/waf/internal/ctxutil"
)
// LibInjectionConfig controls the libinjection middleware.
type LibInjectionConfig struct {
	Enabled   bool
	Threshold int // anomaly points to block (default 2)
}

// LibInjectionStats holds live counters for the libinjection middleware.
type LibInjectionStats struct {
	RequestsScanned atomic.Int64
	SQLIBlocked     atomic.Int64
	XSSBlocked      atomic.Int64
	SQLIDetected    atomic.Int64
	XSSDetected     atomic.Int64
}

// LibInjectionMiddleware inspects all request inputs for SQLi/XSS patterns.
func LibInjectionMiddleware(cfg LibInjectionConfig, rdb *redis.Client, stats *LibInjectionStats) Middleware {
	if !cfg.Enabled {
		return func(next http.Handler) http.Handler { return next }
	}
	threshold := cfg.Threshold
	if threshold <= 0 {
		threshold = 2
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			stats.RequestsScanned.Add(1)

			// Collect all inspectable values
			values := collectInputValues(r)

			sqlScore := 0
			xssScore := 0
			sqlHits := make([]string, 0)
			xssHits := make([]string, 0)

			for _, v := range values {
				if DetectSQLi(v) {
					sqlScore++
					sqlHits = append(sqlHits, truncate(v, 80))
				}
				if DetectXSS(v) {
					xssScore++
					xssHits = append(xssHits, truncate(v, 80))
				}
			}

			// Store in context for logging
			if m := MetricsFromContext(r.Context()); m != nil {
				if sqlScore > 0 || xssScore > 0 {
					total := sqlScore + xssScore
					normalized := float64(total) / float64(threshold)
					if normalized > 1.0 {
						normalized = 1.0
					}
					if normalized > m.ThreatScore {
						m.ThreatScore = normalized
					}
				}
			}

			// Block if threshold exceeded
			if sqlScore >= threshold {
				stats.SQLIBlocked.Add(1)
				if rdb != nil {
					rdb.Incr(r.Context(), "stats:libinjection:sqli_blocked")
				}
				ip := extractIP(r)
				ipStr := ""
				if ip != nil {
					ipStr = ip.String()
				}
				if rdb != nil {
					recordLibinjectionDetection(r.Context(), rdb, "sqli", ipStr, r.URL.Path, strings.Join(sqlHits, "; "))
				}
				log.Printf("libinjection: BLOCKED SQLi %s %s — score %d/%d, hits: %v",
					r.Method, sanitizeLog(r.URL.Path), sqlScore, threshold, sqlHits)
				writeBlockError(w, "LIBINJECTION_SQLI",
					fmt.Sprintf("SQL injection detected (score: %d/%d)", sqlScore, threshold))
				return
			}
			if xssScore >= threshold {
				stats.XSSBlocked.Add(1)
				if rdb != nil {
					rdb.Incr(r.Context(), "stats:libinjection:xss_blocked")
				}
				ip := extractIP(r)
				ipStr := ""
				if ip != nil {
					ipStr = ip.String()
				}
				if rdb != nil {
					recordLibinjectionDetection(r.Context(), rdb, "xss", ipStr, r.URL.Path, strings.Join(xssHits, "; "))
				}
				log.Printf("libinjection: BLOCKED XSS %s %s — score %d/%d, hits: %v",
					r.Method, sanitizeLog(r.URL.Path), xssScore, threshold, xssHits)
				writeBlockError(w, "LIBINJECTION_XSS",
					fmt.Sprintf("XSS injection detected (score: %d/%d)", xssScore, threshold))
				return
			}

			// Log detections below threshold as suspicious
			if sqlScore > 0 {
				stats.SQLIDetected.Add(1)
				log.Printf("libinjection: suspicious SQLi %s %s — score %d/%d",
					r.Method, sanitizeLog(r.URL.Path), sqlScore, threshold)
			}
			if xssScore > 0 {
				stats.XSSDetected.Add(1)
				log.Printf("libinjection: suspicious XSS %s %s — score %d/%d",
					r.Method, sanitizeLog(r.URL.Path), xssScore, threshold)
			}

			next.ServeHTTP(w, r)
		})
	}
}

// recordLibinjectionDetection stores a detection event in Redis for the recent detections list.
func recordLibinjectionDetection(ctx context.Context, rdb *redis.Client, detectionType, clientIP, path, snippet string) {
	if rdb == nil {
		return
	}
	entry := map[string]string{
		"type":      detectionType,
		"client_ip": clientIP,
		"path":      path,
		"snippet":   snippet,
		"time":      time.Now().UTC().Format(time.RFC3339),
	}
	data, _ := json.Marshal(entry)
	rdb.LPush(ctx, "stats:libinjection:recent", data)
	rdb.LTrim(ctx, "stats:libinjection:recent", 0, 49)
}

// collectInputValues extracts all user-controllable string values from the request.
func collectInputValues(r *http.Request) []string {
	var values []string

	// Query parameters
	for _, vs := range r.URL.Query() {
		for _, v := range vs {
			if v != "" {
				values = append(values, v)
			}
		}
	}

	// Body (form-encoded + JSON + multipart)
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		if err := r.ParseForm(); err == nil {
			for _, vs := range r.PostForm {
				for _, v := range vs {
					if v != "" {
						values = append(values, v)
					}
				}
			}
		}
	} else if strings.HasPrefix(ct, "application/json") {
		// P-FIX: previously the libinjection block inspected only form bodies,
		// silently skipping JSON. JSON is the dominant body type for modern
		// APIs; without this fix the entire libinjection pipeline is blind
		// to SQLi/XSS in JSON bodies.
		body, err := ctxutil.ReadOnce(r)
		if err == nil {
			// Restore the body for downstream middleware.
			r.Body = io.NopCloser(bytes.NewReader(body))
			values = append(values, extractJSONStringValues(body)...)
		}
	} else if strings.HasPrefix(ct, "multipart/form-data") {
		// P-FIX: multipart bodies are inspected (best-effort, no file
		// upload) — the form values are already parsed by ParseMultipartForm
		// but only on demand. We trigger a lazy parse to get them.
		if err := r.ParseMultipartForm(1 * 1024 * 1024); err == nil {
			if r.MultipartForm != nil {
				for _, vs := range r.MultipartForm.Value {
					for _, v := range vs {
						if v != "" {
							values = append(values, v)
						}
					}
				}
			}
		}
	}

	// Cookies
	for _, c := range r.Cookies() {
		if c.Value != "" {
			values = append(values, c.Value)
		}
	}

	// Key headers that attackers inject into
	for _, h := range []string{"User-Agent", "Referer", "X-Forwarded-For", "X-Real-IP"} {
		v := r.Header.Get(h)
		if v != "" {
			values = append(values, v)
		}
	}

	return values
}

// extractJSONStringValues walks a JSON document and returns every string
// value found at any depth. Recurses into objects and arrays. Used to feed
// libinjection so JSON request bodies get the same coverage as form bodies.
//
// P-FIX (F-24/F-25): recursion depth is bounded at maxJSONDepth (32) to
// prevent stack overflow on attacker-controlled deeply-nested JSON.
func extractJSONStringValues(data []byte) []string {
	var out []string
	var v any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		// Body wasn't valid JSON — fall back to the raw bytes as a single
		// value so SQLi/XSS inside invalid JSON is still inspected.
		if len(data) > 0 {
			out = append(out, string(data))
		}
		return out
	}
	const maxJSONDepth = 32
	var walk func(any, int)
	walk = func(x any, depth int) {
		if depth > maxJSONDepth {
			return // bail — don't recurse further
		}
		switch t := x.(type) {
		case string:
			if t != "" {
				out = append(out, t)
			}
		case []any:
			for _, e := range t {
				walk(e, depth+1)
			}
		case map[string]any:
			for _, e := range t {
				walk(e, depth+1)
			}
		}
	}
	walk(v, 0)
	return out
}

// --- SQLi Detection ---

// DetectSQLi checks if input contains SQL injection patterns.
// Uses a tokenizer approach inspired by libinjection: tokenize input into SQL
// tokens and check if the sequence matches known injection fingerprints.
func DetectSQLi(input string) bool {
	if len(input) < 3 {
		return false
	}

	score := 0

	// Normalize: lowercase, collapse whitespace
	normalized := strings.ToLower(input)
	normalized = collapseWhitespace(normalized)

	// Quick pattern checks (fast path) — pass both forms so percent-
	// encoded payloads can be detected on the raw input.
	score += checkSQLPatterns(normalized, input)

	// Token-level analysis (uses normalized form).
	tokens := tokenizeSQL(normalized)
	score += analyzeTokenSequence(tokens)

	// The URL-encoded case '%27%20OR...' survives pattern check above
	// (score += 4) but contributes 0 to tokenizeSQL. So a score of
	// exactly 4 should pass. Verify the threshold is reachable.
	return score >= 2
}

// sqlToken represents a classified SQL token.
type sqlToken struct {
	typ  string // "keyword", "operator", "string", "number", "comment", "function", "union", "select", "from", "where", "parens", "semicolon", "literal", "other"
	text string
}

// tokenizeSQL splits input into SQL-like tokens.
func tokenizeSQL(input string) []sqlToken {
	var tokens []sqlToken
	i := 0
	runes := []rune(input)

	for i < len(runes) {
		ch := runes[i]

		// Skip whitespace
		if unicode.IsSpace(ch) {
			i++
			continue
		}

		// String literals (single or double quoted)
		if ch == '\'' || ch == '"' {
			end := findStringEnd(runes, i)
			if end > i {
				tokens = append(tokens, sqlToken{typ: "string", text: string(runes[i:end])})
				i = end
				continue
			}
		}

		// Comment patterns: -- , /* , #
		if ch == '-' && i+1 < len(runes) && runes[i+1] == '-' {
			tokens = append(tokens, sqlToken{typ: "comment", text: "--"})
			i += 2
			continue
		}
		if ch == '/' && i+1 < len(runes) && runes[i+1] == '*' {
			tokens = append(tokens, sqlToken{typ: "comment", text: "/*"})
			i += 2
			continue
		}
		if ch == '#' {
			tokens = append(tokens, sqlToken{typ: "comment", text: "#"})
			i++
			continue
		}

		// Numbers
		if unicode.IsDigit(ch) {
			j := i
			for j < len(runes) && (unicode.IsDigit(runes[j]) || runes[j] == '.') {
				j++
			}
			tokens = append(tokens, sqlToken{typ: "number", text: string(runes[i:j])})
			i = j
			continue
		}

		// Operators
		if strings.ContainsRune("=<>!|&+-*/%", ch) {
			j := i + 1
			for j < len(runes) && strings.ContainsRune("=<>!|&", runes[j]) {
				j++
			}
			tokens = append(tokens, sqlToken{typ: "operator", text: string(runes[i:j])})
			i = j
			continue
		}

		// Parens, semicolons
		if ch == '(' || ch == ')' {
			tokens = append(tokens, sqlToken{typ: "parens", text: string(ch)})
			i++
			continue
		}
		if ch == ';' {
			tokens = append(tokens, sqlToken{typ: "semicolon", text: ";"})
			i++
			continue
		}

		// Words (identifiers, keywords)
		if unicode.IsLetter(ch) || ch == '_' || ch == '@' {
			j := i
			for j < len(runes) && (unicode.IsLetter(runes[j]) || unicode.IsDigit(runes[j]) || runes[j] == '_' || runes[j] == '@') {
				j++
			}
			word := string(runes[i:j])
			tokType := classifySQLWord(word)
			tokens = append(tokens, sqlToken{typ: tokType, text: word})
			i = j
			continue
		}

		// Skip other characters
		i++
	}

	return tokens
}

// classifySQLWord determines the token type for a SQL word.
func classifySQLWord(word string) string {
	switch word {
	case "union", "intersect", "except":
		return "union"
	case "select":
		return "select"
	case "from":
		return "from"
	case "where", "having", "on":
		return "where"
	case "insert", "into", "values":
		return "keyword"
	case "update", "set":
		return "keyword"
	case "delete":
		return "keyword"
	case "drop", "alter", "create", "truncate":
		return "keyword"
	case "exec", "execute":
		return "keyword"
	case "and", "or", "not", "xor":
		return "operator"
	case "null", "true", "false":
		return "literal"
	case "concat", "group_concat", "substr", "substring", "char", "ascii",
		"hex", "unhex", "length", "replace", "if", "ifnull", "coalesce",
		"sleep", "benchmark", "waitfor", "dbms_pipe", "utl_http",
		"httprequest", "dbms_lock":
		return "function"
	case "information_schema", "sysobjects", "syscolumns", "mysql",
		"pg_catalog", "pg_sleep":
		return "keyword"
	case "table", "column", "database", "schema", "index":
		return "keyword"
	case "declare", "cast", "convert":
		return "keyword"
	case "like", "between", "in", "exists", "any", "all":
		return "operator"
	case "order", "group", "limit", "offset":
		return "keyword"
	default:
		return "other"
	}
}

// analyzeTokenSequence checks a token list for SQL injection fingerprints.
func analyzeTokenSequence(tokens []sqlToken) int {
	if len(tokens) < 2 {
		return 0
	}
	score := 0

	for i := 0; i < len(tokens)-1; i++ {
		a, b := tokens[i], tokens[i+1]

		// UNION SELECT
		if a.typ == "union" && b.typ == "select" {
			score += 3
		}

		// SELECT ... FROM
		if a.typ == "select" && b.typ == "from" {
			score += 2
		}

		// INSERT INTO / DELETE FROM / DROP TABLE
		if (a.text == "insert" && b.text == "into") ||
			(a.text == "delete" && b.text == "from") ||
			(a.text == "drop" && b.typ == "keyword") {
			score += 3
		}

		// OR/AND followed by always-true: 1=1
		if (a.text == "or" || a.text == "and") && b.typ == "number" {
			if i+2 < len(tokens) && tokens[i+2].text == "=" {
				score += 2
			}
		}

		// Comment injection after content
		if b.typ == "comment" && a.typ != "comment" {
			score += 1
		}

		// Semicolon followed by keyword (statement stacking)
		if a.typ == "semicolon" && b.typ != "other" {
			score += 2
		}

		// EXEC / EXECUTE
		if a.text == "exec" || a.text == "execute" {
			score += 2
		}

		// Sleep/benchmark (timing attacks)
		if a.typ == "function" && (a.text == "sleep" || a.text == "benchmark" || a.text == "waitfor") {
			score += 3
		}

		// information_schema access
		if a.text == "information_schema" || a.text == "sysobjects" {
			score += 3
		}

		// String break-out: string followed by operator/keyword
		if a.typ == "string" && (b.typ == "operator" || b.typ == "union" || b.text == "or" || b.text == "and") {
			score += 2
		}
	}

	// Stacked queries
	semicolonCount := 0
	for _, t := range tokens {
		if t.typ == "semicolon" {
			semicolonCount++
		}
	}
	if semicolonCount > 0 {
		score += semicolonCount
	}

	return score
}

// checkSQLPatterns does fast string-pattern checks for common SQLi signatures.
func checkSQLPatterns(normalized, input string) int {
	score := 0

	// UNION SELECT variants
	if strings.Contains(normalized, "union select") || strings.Contains(normalized, "union all select") {
		score += 3
	}

	// Classic tautologies
	if strings.Contains(normalized, "' or '1'='1") || strings.Contains(normalized, "' or 1=1") ||
		strings.Contains(normalized, "\" or \"1\"=\"1") || strings.Contains(normalized, "\" or 1=1") ||
		strings.Contains(normalized, "or 1=1") || strings.Contains(normalized, "or true") {
		score += 3
	}
	// URL-encoded SQLi: %27%20OR%201%3D1-- (%27=', %20=space, %3D==)
	// The body inspector already URL-decodes args, but query strings
	// may carry percent-encoded payloads. Use the raw input so percent
	// sequences are preserved. We accept "or" / "and" as either with
	// a literal space OR with %20/+ in place of the space.
	inputLower := strings.ToLower(input)
	hasEncodedQuote := strings.Contains(inputLower, "%27")
	hasEncodedSpace := strings.Contains(inputLower, "%20") || strings.Contains(inputLower, "+")
	hasOrSpace := strings.Contains(inputLower, "or ") || strings.Contains(inputLower, "and ")
	hasEncodedOr := strings.Contains(inputLower, "or%20") || strings.Contains(inputLower, "and%20") ||
		strings.Contains(inputLower, "or+") || strings.Contains(inputLower, "and+")
	if hasEncodedQuote && (hasOrSpace || hasEncodedOr) && hasEncodedSpace {
		score += 4
	}
	// Admin/auth bypass with comment terminator (admin'--, admin'/*)
	if (strings.Contains(normalized, "admin'") || strings.Contains(normalized, "root'") || strings.Contains(normalized, "user'")) &&
		(strings.Contains(normalized, "--") || strings.Contains(normalized, "#")) {
		score += 4
	}
	// Paren-then-tautology: ') OR ('1'='1, ) OR (1=1)
	if strings.Contains(normalized, ") or (") || strings.Contains(normalized, ") and (") {
		score += 3
	}
	// PostgreSQL cast operator: '::int, '::text
	if strings.Contains(normalized, "'::") || strings.Contains(normalized, "\"::") {
		score += 3
	}

	// Destructive keywords
	if strings.Contains(normalized, "drop table") || strings.Contains(normalized, "drop database") ||
		strings.Contains(normalized, "truncate table") {
		score += 3
	}

	// Insert/Delete injection
	if strings.Contains(normalized, "insert into") && strings.Contains(normalized, "values") {
		score += 2
	}
	if strings.Contains(normalized, "delete from") {
		score += 2
	}

	// Information schema probing
	if strings.Contains(normalized, "information_schema") || strings.Contains(normalized, "sysobjects") ||
		strings.Contains(normalized, "pg_catalog") {
		score += 3
	}

	// Execution functions
	if strings.Contains(normalized, "exec(") || strings.Contains(normalized, "execute(") ||
		strings.Contains(normalized, "exec ") || strings.Contains(normalized, "execute immediate") {
		score += 2
	}

	// Timing attacks
	if strings.Contains(normalized, "sleep(") || strings.Contains(normalized, "benchmark(") ||
		strings.Contains(normalized, "waitfor delay") || strings.Contains(normalized, "pg_sleep") {
		score += 3
	}

	// CHAR() for bypassing filters
	if strings.Contains(normalized, "char(") || strings.Contains(normalized, "chr(") {
		score += 2
	}

	// Hex encoding bypass
	if strings.Contains(normalized, "0x") && len(normalized) > 4 {
		score += 1
	}

	return score
}

// --- XSS Detection ---

// DetectXSS checks if input contains XSS patterns.
func DetectXSS(input string) bool {
	if len(input) < 6 {
		return false
	}

	lower := strings.ToLower(input)
	score := 0

	// Script tags
	if strings.Contains(lower, "<script") || strings.Contains(lower, "</script") {
		score += 4
	}

	// JavaScript protocol
	if strings.Contains(lower, "javascript:") || strings.Contains(lower, "vbscript:") ||
		strings.Contains(lower, "data:text/html") {
		score += 4
	}
	// Dangerous embed / object / iframe with remote src
	if (strings.Contains(lower, "<iframe") || strings.Contains(lower, "<object") || strings.Contains(lower, "<embed")) &&
		(strings.Contains(lower, "src=") || strings.Contains(lower, "data=")) {
		score += 4
	}
	// JS template literal / expression: ${...}
	if strings.Contains(input, "${") {
		score += 2
	}

	// Event handlers
	xssEventPatterns := []string{
		"onerror", "onload", "onmouseover", "onmouseout", "onclick", "onfocus",
		"onblur", "onsubmit", "onchange", "onkeydown", "onkeyup", "onkeypress",
		"onmouseenter", "onmouseleave", "oninput", "oninvalid", "ontouchstart",
		"onanimationstart", "ontransitionend", "onscroll", "onwheel",
	}
	for _, p := range xssEventPatterns {
		if strings.Contains(lower, p+"=") {
			score += 3
		}
	}

	// Dangerous tags
	dangerousTags := []string{"<iframe", "<object", "<embed", "<applet", "<form",
		"<meta", "<link", "<svg", "<math", "<marquee", "<details", "<dialog", "<template"}
	for _, tag := range dangerousTags {
		if strings.Contains(lower, tag) {
			score += 2
		}
	}

	// SVG with event handlers
	if strings.Contains(lower, "<svg") && (strings.Contains(lower, "onload") || strings.Contains(lower, "onerror")) {
		score += 4
	}

	// Expression()/eval()
	if strings.Contains(lower, "expression(") || strings.Contains(lower, "eval(") {
		score += 3
	}

	// Base64 data URIs
	if strings.Contains(lower, "data:") && strings.Contains(lower, "base64") {
		score += 3
	}

	// Document/window access
	if strings.Contains(lower, "document.cookie") || strings.Contains(lower, "document.domain") ||
		strings.Contains(lower, "document.write") || strings.Contains(lower, "window.location") {
		score += 3
	}

	// Alert/confirm/prompt
	if strings.Contains(lower, "alert(") || strings.Contains(lower, "confirm(") ||
		strings.Contains(lower, "prompt(") {
		score += 2
	}

	// Encoded variants
	if strings.Contains(lower, "&lt;script") || strings.Contains(lower, "&#x3c;script") {
		score += 2
	}

	// Template injection
	if strings.Contains(input, "{{") && strings.Contains(input, "}}") {
		score += 1
	}

	return score >= 3
}

// --- Helpers ---

// findStringEnd finds the end of a quoted string starting at position i.
func findStringEnd(runes []rune, i int) int {
	quote := runes[i]
	j := i + 1
	for j < len(runes) {
		if runes[j] == '\\' {
			j += 2
			continue
		}
		if runes[j] == quote {
			return j + 1
		}
		j++
	}
	return i + 1
}

// collapseWhitespace replaces all runs of whitespace with a single space.
func collapseWhitespace(s string) string {
	var b strings.Builder
	inSpace := false
	for _, r := range s {
		if unicode.IsSpace(r) {
			if !inSpace {
				b.WriteRune(' ')
				inSpace = true
			}
		} else {
			b.WriteRune(r)
			inSpace = false
		}
	}
	return b.String()
}

// truncate shortens a string to maxLen characters with "..." suffix.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
