package middleware

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/redis/go-redis/v9"
	"github.com/user/waf/internal/ctxutil"
)
const (
	bodyInspectMaxRead int64 = 1 << 20 // 1MB, matches bodySizeMiddleware
	// H-11: caps for individual JSON / form / multipart keys and values
	// to prevent unbounded allocation from a payload like {"<2MB key>": x}.
	bodyInspectMaxKeyLen   = 256
	bodyInspectMaxValueLen = 4096
	bodyInspectMaxValues   = 2048
)

// BodyInspector inspects request bodies for attack patterns.
type BodyInspector struct {
	enabled         bool
	inspectJSON     bool
	inspectForm     bool
	inspectMultipart bool
	inspectXML      bool
	inspectText     bool
	maxBodySize     int64 // max bytes to inspect; 0 = use default 1MB
	hardBodyLimit   int64 // block request if body exceeds this; 0 = no hard limit
	rdb             *redis.Client
	stats           *bodyInspectStats
}

// NewBodyInspector creates a body inspection middleware.
func NewBodyInspector(enabled, inspectJSON, inspectForm, inspectMultipart, inspectXML, inspectText bool, rdb *redis.Client) *BodyInspector {
	return NewBodyInspectorWithLimits(enabled, inspectJSON, inspectForm, inspectMultipart, inspectXML, inspectText, 1<<20, 0, rdb)
}

// NewBodyInspectorWithLimits creates a body inspector with configurable size limits.
// maxBodySize: bytes to inspect (default 1MB)
// hardBodyLimit: block if body exceeds this (0=no hard block, just skip inspection beyond maxBodySize)
func NewBodyInspectorWithLimits(enabled, inspectJSON, inspectForm, inspectMultipart, inspectXML, inspectText bool, maxBodySize, hardBodyLimit int64, rdb *redis.Client) *BodyInspector {
	if maxBodySize == 0 {
		maxBodySize = 1 << 20
	}
	return &BodyInspector{
		enabled:         enabled,
		inspectJSON:     inspectJSON,
		inspectForm:     inspectForm,
		inspectMultipart: inspectMultipart,
		inspectXML:      inspectXML,
		inspectText:     inspectText,
		maxBodySize:     maxBodySize,
		hardBodyLimit:   hardBodyLimit,
		rdb:             rdb,
		stats: &bodyInspectStats{
			TopAttacks: make(map[string]int64),
		},
	}
}

type bodyInspectStats struct {
	mu              sync.Mutex
	ParsedJSON      int64 `json:"parsed_json"`
	ParsedForm      int64 `json:"parsed_form"`
	ParsedMultipart int64 `json:"parsed_multipart"`
	ParsedXML       int64 `json:"parsed_xml"`
	ParsedText      int64 `json:"parsed_text"`
	GRPCRequests    int64 `json:"grpc_requests"`
	ThreatsFound    int64 `json:"threats_found"`
	Truncated       int64 `json:"truncated"`
	TopAttacks      map[string]int64 `json:"top_attacks"`
}

// BodyInspectStats is the public stats snapshot for API responses.
type BodyInspectStats struct {
	Enabled         bool             `json:"enabled"`
	ParsedJSON      int64            `json:"parsed_json"`
	ParsedForm      int64            `json:"parsed_form"`
	ParsedMultipart int64            `json:"parsed_multipart"`
	ParsedXML       int64            `json:"parsed_xml"`
	ParsedText      int64            `json:"parsed_text"`
	GRPCRequests    int64            `json:"grpc_requests"`
	ThreatsFound    int64            `json:"threats_found"`
	Truncated       int64            `json:"truncated"`
	TopAttacks      map[string]int64 `json:"top_attacks"`
}

// Stats returns a snapshot of body inspection statistics.
func (bi *BodyInspector) Stats() BodyInspectStats {
	bi.stats.mu.Lock()
	defer bi.stats.mu.Unlock()

	topAttacks := make(map[string]int64, len(bi.stats.TopAttacks))
	for k, v := range bi.stats.TopAttacks {
		topAttacks[k] = v
	}
	return BodyInspectStats{
		Enabled:         bi.enabled,
		ParsedJSON:      atomic.LoadInt64(&bi.stats.ParsedJSON),
		ParsedForm:      atomic.LoadInt64(&bi.stats.ParsedForm),
		ParsedMultipart: atomic.LoadInt64(&bi.stats.ParsedMultipart),
		ParsedXML:       atomic.LoadInt64(&bi.stats.ParsedXML),
		ParsedText:      atomic.LoadInt64(&bi.stats.ParsedText),
		GRPCRequests:    atomic.LoadInt64(&bi.stats.GRPCRequests),
		ThreatsFound:    atomic.LoadInt64(&bi.stats.ThreatsFound),
		Truncated:       atomic.LoadInt64(&bi.stats.Truncated),
		TopAttacks:      topAttacks,
	}
}

// SetEnabled toggles body inspection on/off.
func (bi *BodyInspector) SetEnabled(v bool) {
	bi.enabled = v
}

// Middleware returns HTTP middleware that inspects request bodies for attacks.
func (bi *BodyInspector) Middleware(next http.Handler) http.Handler {
	if !bi.enabled {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only inspect methods with bodies
		if r.Method != "POST" && r.Method != "PUT" && r.Method != "PATCH" {
			next.ServeHTTP(w, r)
			return
		}

		if r.Body == nil || r.Body == http.NoBody {
			next.ServeHTTP(w, r)
			return
		}

		maxRead := bi.maxBodySize
		if maxRead == 0 {
			maxRead = 1 << 20
		}
		bodyBytes, err := ctxutil.ReadOnce(r)
		if err != nil || len(bodyBytes) == 0 {
			// P-FIX (L-5): distinguish a clean read returning 0 bytes
			// from a partial + error. If we hit an EOF mid-body we may
			// have a truncated payload that the inspection layer would
			// treat as valid; surface the error to the caller via a
			// truncated marker.
			if err != nil && len(bodyBytes) > 0 {
				atomic.AddInt64(&bi.stats.Truncated, 1)
				log.Printf("bodyinspect: %s %s — partial read (%d bytes): %v",
					r.Method, sanitizeLog(r.URL.Path), len(bodyBytes), err)
			}
			if len(bodyBytes) > 0 {
				r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			}
			next.ServeHTTP(w, r)
			return
		}

		// Explicitly handle oversized payloads instead of silently passing them
		if bi.hardBodyLimit > 0 && int64(len(bodyBytes)) > bi.hardBodyLimit {
			log.Printf("bodyinspect: body exceeds hard limit (%d bytes, limit=%d) from %s — blocked",
				len(bodyBytes), bi.hardBodyLimit, sanitizeLog(extractIP(r).String()))
			writeBlockError(w, "PAYLOAD_TOO_LARGE",
				fmt.Sprintf("request body exceeds maximum allowed size of %d bytes", bi.hardBodyLimit))
			return
		}

		// If body exceeds inspect limit, truncate and record
		if int64(len(bodyBytes)) > maxRead {
			bodyBytes = bodyBytes[:maxRead]
			if bi.rdb != nil {
				bi.rdb.Incr(r.Context(), "stats:body_inspect:truncated")
			}
		}

		// Restore body for downstream handlers
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		ct := r.Header.Get("Content-Type")
		baseCT, params, _ := mime.ParseMediaType(ct)

		var findings []string
		var threatScore float64

		switch {
		case (baseCT == "application/json" || strings.HasPrefix(ct, "application/json")) && bi.inspectJSON:
			atomic.AddInt64(&bi.stats.ParsedJSON, 1)
			findings, threatScore = bi.inspectJSONBody(bodyBytes)

		case (baseCT == "application/x-www-form-urlencoded") && bi.inspectForm:
			atomic.AddInt64(&bi.stats.ParsedForm, 1)
			findings, threatScore = bi.inspectFormBody(bodyBytes)

		case strings.HasPrefix(baseCT, "multipart/") && bi.inspectMultipart:
			atomic.AddInt64(&bi.stats.ParsedMultipart, 1)
			// L-9: pass the already-parsed params to avoid a second
			// mime.ParseMediaType call inside inspectMultipartBody.
			findings, threatScore = bi.inspectMultipartBodyWithParams(r, bodyBytes, params)

		case (baseCT == "application/xml" || baseCT == "text/xml" || strings.HasSuffix(baseCT, "+xml")) && bi.inspectXML:
			atomic.AddInt64(&bi.stats.ParsedXML, 1)
			findings, threatScore = bi.inspectXMLBody(bodyBytes)

		case strings.HasPrefix(baseCT, "text/") && bi.inspectText:
			atomic.AddInt64(&bi.stats.ParsedText, 1)
			findings, threatScore = bi.inspectTextBody(bodyBytes)

		case baseCT == "application/grpc" || strings.HasSuffix(ct, "+proto") || strings.Contains(ct, "application/grpc"):
			findings, threatScore = bi.inspectGRPCBody(bodyBytes)
		}

		if len(findings) > 0 {
			atomic.AddInt64(&bi.stats.ThreatsFound, 1)
			bi.recordAttackTypes(findings)

			// Store in request metrics
			if m := MetricsFromContext(r.Context()); m != nil {
				m.BodyFindings = findings
				if threatScore > m.BodyThreatScore {
					m.BodyThreatScore = threatScore
				}
				if threatScore > m.ThreatScore {
					m.ThreatScore = threatScore
				}
			}

			// Increment Redis counter
			if bi.rdb != nil {
				bi.rdb.Incr(r.Context(), "stats:body_inspect:threats")
			}

			log.Printf("bodyinspect: %s %s — %d findings: [%s]",
				r.Method, sanitizeLog(r.URL.Path), len(findings), sanitizeLog(strings.Join(findings, ", ")))
		}

		next.ServeHTTP(w, r)
	})
}

func (bi *BodyInspector) recordAttackTypes(findings []string) {
	bi.stats.mu.Lock()
	defer bi.stats.mu.Unlock()
	for _, f := range findings {
		// Extract attack type from finding format "type: detail"
		attackType := f
		if idx := strings.Index(f, ":"); idx > 0 {
			attackType = f[:idx]
		}
		bi.stats.TopAttacks[attackType]++
	}
}

// --- Body type inspectors ---

// inspectJSONBody parses JSON and recursively extracts all string values for inspection.
func (bi *BodyInspector) inspectJSONBody(body []byte) ([]string, float64) {
	var raw interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, 0
	}
	values := extractJSONStrings(raw, "")
	return inspectValues(values)
}

func extractJSONStrings(v interface{}, path string) []string {
	var results []string
	// H-11: refuse to return more than bodyInspectMaxValues strings from a
	// single body. An attacker can otherwise craft a JSON payload with tens
	// of thousands of duplicate keys to balloon allocation in inspectValues.
	const hardCap = bodyInspectMaxValues
	if len(results) >= hardCap {
		return results
	}
	switch val := v.(type) {
	case string:
		results = append(results, val)
	case map[string]interface{}:
		for k, child := range val {
			key := k
			if len(key) > bodyInspectMaxKeyLen {
				key = key[:bodyInspectMaxKeyLen]
			}
			childPath := path + "." + key
			results = append(results, extractJSONStrings(child, childPath)...)
			if len(results) >= hardCap {
				return results
			}
		}
	case []interface{}:
		for i, child := range val {
			childPath := fmt.Sprintf("%s[%d]", path, i)
			results = append(results, extractJSONStrings(child, childPath)...)
			if len(results) >= hardCap {
				return results
			}
		}
	}
	return results
}

// inspectFormBody parses URL-encoded form data.
func (bi *BodyInspector) inspectFormBody(body []byte) ([]string, float64) {
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, 0
	}
	var allValues []string
	for k, vs := range values {
		if len(allValues) >= bodyInspectMaxValues {
			break
		}
		// H-11: cap individual form keys; a key like "a"*30000 would
		// otherwise be passed to the regex engine unsanitized.
		if len(k) > bodyInspectMaxKeyLen {
			k = k[:bodyInspectMaxKeyLen]
		}
		allValues = append(allValues, k)
		for _, v := range vs {
			if len(allValues) >= bodyInspectMaxValues {
				break
			}
			allValues = append(allValues, v)
		}
	}
	return inspectValues(allValues)
}

// inspectMultipartBody parses multipart form data, inspecting field values and file metadata.
func (bi *BodyInspector) inspectMultipartBody(r *http.Request, body []byte) ([]string, float64) {
	ct := r.Header.Get("Content-Type")
	_, params, err := mime.ParseMediaType(ct)
	if err != nil {
		return nil, 0
	}
	return bi.inspectMultipartBodyWithParams(r, body, params)
}

// inspectMultipartBodyWithParams is the L-9 helper that accepts the
// already-parsed media-type params so the middleware can avoid a
// second mime.ParseMediaType call.
func (bi *BodyInspector) inspectMultipartBodyWithParams(r *http.Request, body []byte, params map[string]string) ([]string, float64) {
	if len(params) == 0 {
		return nil, 0
	}
	boundary, ok := params["boundary"]
	if !ok {
		return nil, 0
	}

	var allValues []string
	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	for {
		part, err := reader.NextPart()
		if err != nil {
			break
		}
		// Inspect field name and filename
		if part.FormName() != "" {
			allValues = append(allValues, part.FormName())
		}
		if part.FileName() != "" {
			allValues = append(allValues, part.FileName())
			// Also check content type of file uploads
			if part.Header.Get("Content-Type") != "" {
				allValues = append(allValues, part.Header.Get("Content-Type"))
			}
		}
		// Read field value (limit to 64KB per field)
		fieldData, _ := io.ReadAll(io.LimitReader(part, 64*1024))
		if len(fieldData) > 0 {
			allValues = append(allValues, string(fieldData))
		}
		part.Close()
	}
	return inspectValues(allValues)
}

// inspectXMLBody parses XML and extracts all text content.
func (bi *BodyInspector) inspectXMLBody(body []byte) ([]string, float64) {
	// F11: pre-scan for XXE / billion-laughs style payloads that some
	// payloads try to bypass by inserting whitespace or splitting tokens,
	// e.g. "<!ENT ITY ...>" or "<!ENTITY\n...". Match ENT followed by
	// optional whitespace then ITY (case-insensitive).
	if xxeEntPattern.Match(body) {
		return []string{"xxe: entity-decl-fragment"}, 1.0
	}
	if xxeSysPattern.Match(body) {
		return []string{"xxe: external-system"}, 1.0
	}

	decoder := xml.NewDecoder(bytes.NewReader(body))
	decoder.Strict = false
	var texts []string
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.CharData:
			s := strings.TrimSpace(string(t))
			if s != "" {
				texts = append(texts, s)
			}
		case xml.StartElement:
			// Inspect attribute values
			for _, attr := range t.Attr {
				texts = append(texts, attr.Value)
			}
		}
	}
	return inspectValues(texts)
}

// inspectTextBody inspects raw text body.
func (bi *BodyInspector) inspectTextBody(body []byte) ([]string, float64) {
	return inspectValues([]string{string(body)})
}

// --- Threat pattern matching ---

var (
	bodyOnce     sync.Once
	sqliPatterns []*regexp.Regexp
	xssPatterns  []*regexp.Regexp
	traversalPatterns []*regexp.Regexp
	cmdPatterns  []*regexp.Regexp
	ssrfPatterns []*regexp.Regexp
	// F11: explicit XXE / external-entity detection. The Go xml package
	// does not resolve external entities by default, but a payload can
	// still leak sensitive paths or be a smuggling vector. Match with
	// optional whitespace between tokens to defeat "<!ENT ITY ...>".
	xxeEntPattern = regexp.MustCompile(`(?is)<!\s*ENT\s*ITY\b`)
	xxeSysPattern = regexp.MustCompile(`(?is)<!\s*DOCTYPE[^>]*\bSYSTEM\b`)
)

func initBodyPatterns() {
	sqliPatterns = compilePatterns([]string{
		`(?i)(union\s+select|select\s+.*\s+from\s+|insert\s+into|delete\s+from|drop\s+table|update\s+.*\s+set\s+)`,
		`(?i)('\s*or\s*'|'\s*or\s+\d+\s*=\s*\d+|"\s*or\s+\d+\s*=\s*\d+)`,
		`(?i)(;\s*--|;\s*drop\s|;\s*alter\s|;\s*truncate\s)`,
		`(?i)(/\*.*\*/|--\s+[^\n]*|;\s*--)`,
		`(?i)(benchmark\s*\(|sleep\s*\(|waitfor\s+delay|pg_sleep)`,
		`(?i)(load_file\s*\(|into\s+outfile|into\s+dumpfile)`,
	})

	xssPatterns = compilePatterns([]string{
		`(?i)<\s*script[\s>]`,
		`(?i)(on\w+\s*=|javascript\s*:|vbscript\s*:)`,
		`(?i)<\s*(iframe|object|embed|applet|form|svg)\s`,
		`(?i)(alert\s*\(|confirm\s*\(|prompt\s*\(|document\.cookie|document\.write)`,
		`(?i)<\s*img\s[^>]*src\s*=\s*["']?\s*javascript:`,
	})

	traversalPatterns = compilePatterns([]string{
		// F47: also match overlong-UTF8 sequences (%c0%ae = 0xC0 0xAE
		// and %c1%1c = 0xC1 0x9C). These decode to '.' and '/'
		// respectively on servers that don't reject non-minimal UTF-8.
		`(?i)(\.\./|\.\.\\|%2e%2e%2f|%2e%2e%5c|%252e%252e%252f|%c0%ae%c0%ae/|%c1%9c|%e0%80%af)`,
		`(/etc/passwd|/etc/shadow|/proc/self|/etc/hosts)`,
		`(C:\\Windows\\|C:\\boot\.ini)`,
	})

	cmdPatterns = compilePatterns([]string{
		`(?i)(;\s*(ls|cat|whoami|id|uname|ifconfig|netstat|wget|curl|ping|nslookup|dig)\b)`,
		`(?i)(\|\s*(ls|cat|whoami|id|uname)\b)`,
		"(`[^`]*`)",  // backtick execution
		`(\$\([^)]*\))`, // $() command substitution
		`(?i)(exec\s*\(|system\s*\(|passthru\s*\(|shell_exec\s*\()`,
	})

	ssrfPatterns = compilePatterns([]string{
		`(?i)(file://|gopher://|dict://|ftp://|tftp://)`,
		`(?i)(169\.254\.169\.254|metadata\.google|metadata\.aws)`,
		`(?i)(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])`,
	})
}

func compilePatterns(patterns []string) []*regexp.Regexp {
	var compiled []*regexp.Regexp
	for _, p := range patterns {
		if re, err := regexp.Compile(p); err == nil {
			compiled = append(compiled, re)
		}
	}
	return compiled
}

func inspectValues(values []string) ([]string, float64) {
	bodyOnce.Do(initBodyPatterns)

	var findings []string
	seen := make(map[string]bool)

	// H-11: bound the number of inputs we inspect so a payload with N
	// repeated strings costs O(N) regex evaluations. The cap is enforced
	// by the callers too, this is a defence-in-depth.
	if len(values) > bodyInspectMaxValues {
		values = values[:bodyInspectMaxValues]
	}
	for _, v := range values {
		if len(v) > 4096 {
			v = v[:4096] // limit per-value inspection length
		}
		for _, re := range sqliPatterns {
			if re.MatchString(v) {
				f := "sqli: " + re.String()
				if !seen[f] {
					findings = append(findings, f)
					seen[f] = true
				}
			}
		}
		for _, re := range xssPatterns {
			if re.MatchString(v) {
				f := "xss: " + re.String()
				if !seen[f] {
					findings = append(findings, f)
					seen[f] = true
				}
			}
		}
		for _, re := range traversalPatterns {
			if re.MatchString(v) {
				f := "traversal: " + re.String()
				if !seen[f] {
					findings = append(findings, f)
					seen[f] = true
				}
			}
		}
		for _, re := range cmdPatterns {
			if re.MatchString(v) {
				f := "cmd_injection: " + re.String()
				if !seen[f] {
					findings = append(findings, f)
					seen[f] = true
				}
			}
		}
		for _, re := range ssrfPatterns {
			if re.MatchString(v) {
				f := "ssrf: " + re.String()
				if !seen[f] {
					findings = append(findings, f)
					seen[f] = true
				}
			}
		}
	}

	// Score: 0.2 per finding category, capped at 1.0
	score := float64(len(findings)) * 0.2
	if score > 1.0 {
		score = 1.0
	}
	return findings, score
}

// inspectGRPCBody inspects raw protobuf bytes for attack signatures.
func (bi *BodyInspector) inspectGRPCBody(body []byte) ([]string, float64) {
	// gRPC uses protobuf. We scan the wire bytes for known attack patterns.
	// Full protobuf decoding would require schema introspection; this is a basic approach.
	return inspectBytePatterns(body, 0.15)
}

// inspectBytePatterns scans raw bytes for attack signatures.
func inspectBytePatterns(data []byte, perFinding float64) ([]string, float64) {
	var findings []string
	seen := make(map[string]bool)

	// F46: the previous list mixed literal substrings and REGEX
	// metacharacters (e.g. "select.*from"). The literal-contains check
	// below can NEVER match the dot-star tokens; the engine would
	// silently drop every "select.*from" payload. Switch the regex-shaped
	// entry to an actual regexp.
	literalPatterns := []string{"union select", "drop table", "--", "/*", "benchmark(", "sleep(", "../", "..\\", "file://", "gopher://", "exec(", "system(", "shell_exec("}
	for _, p := range literalPatterns {
		if contains(data, []byte(p)) {
			f := "payload: " + p
			if !seen[f] {
				findings = append(findings, f)
				seen[f] = true
			}
		}
	}
	// Regex-shaped pattern (compiled once).
	if selectFromRegexp.Match(data) {
		f := "payload: select.*from"
		if !seen[f] {
			findings = append(findings, f)
			seen[f] = true
		}
	}

	score := float64(len(findings)) * perFinding
	if score > 1.0 {
		score = 1.0
	}
	return findings, score
}

// selectFromRegexp matches `select` followed by any whitespace-containing
// payload followed by `from`. F46: replacing the dead literal ".*from"
// entry from the patterns table.
var selectFromRegexp = regexp.MustCompile(`(?i)select\s+.*\s+from\s+`)

func contains(data []byte, pattern []byte) bool {
	for i := 0; i <= len(data)-len(pattern); i++ {
		if string(data[i:i+len(pattern)]) == string(pattern) {
			return true
		}
	}
	return false
}
