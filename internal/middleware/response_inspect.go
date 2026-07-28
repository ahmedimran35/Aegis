package middleware

import (
	"bytes"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/redis/go-redis/v9"
)

const maxInspectSize = 64 * 1024 // 64KB

type inspectCategory struct {
	name     string
	patterns []*regexp.Regexp
}

var (
	inspectOnce     sync.Once
	inspectPatterns []inspectCategory
)

func initInspectPatterns() {
	categories := []struct {
		name  string
		regex []string
	}{
		{
			name: "SQL error",
			regex: []string{
				`(?i)SQL syntax`, `(?i)mysql_fetch`, `(?i)ORA-\d{5}`,
				`(?i)PostgreSQL.*ERROR`, `(?i)SQLite3::`, `(?i)Unclosed quotation mark`,
			},
		},
		{
			name: "stack trace",
			regex: []string{
				`(?i)Traceback \(most recent call last\)`, `at \w+\.\w+\(`,
				`(?i)Exception in thread`, `(?i)NullPointerException`, `(?i)System\.NullReferenceException`,
			},
		},
		{
			name: "PHP error",
			regex: []string{
				`(?i)Fatal error:`, `(?i)Parse error:`, `(?i)Warning:\s+include`,
				`(?i)Notice:\s+Undefined`, `(?i)Fatal error.*on line`,
			},
		},
		{
			name: "server version disclosure",
			regex: []string{
				`(?m)^Server:`, `(?m)^X-Powered-By:`, `Apache/\d`, `nginx/\d`, `PHP/\d`,
			},
		},
		{
			name: "internal IP",
			regex: []string{
				`192\.168\.\d+\.\d+`, `10\.\d+\.\d+\.\d+`, `172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+`,
			},
		},
		{
			name: "web shell",
			regex: []string{
				`eval\(base64_decode`, `eval\(\$_`, `system\(\$_`, `passthru`, `shell_exec`,
			},
		},
		{
			name: "sensitive path",
			regex: []string{
				`/etc/passwd`, `/proc/self`, `C:\\Windows\\`, `/var/log/`,
			},
		},
	}

	inspectPatterns = make([]inspectCategory, 0, len(categories))
	for _, c := range categories {
		cat := inspectCategory{name: c.name}
		for _, r := range c.regex {
			cat.patterns = append(cat.patterns, regexp.MustCompile(r))
		}
		inspectPatterns = append(inspectPatterns, cat)
	}
}

// ResponseInspector inspects server responses for data leakage.
type ResponseInspector struct {
	enabled      bool
	blockOnLeak  bool
	rdb          *redis.Client
}

// NewResponseInspector creates a response body inspector.
func NewResponseInspector(enabled, blockOnLeak bool, rdb *redis.Client) *ResponseInspector {
	inspectOnce.Do(initInspectPatterns)
	return &ResponseInspector{enabled: enabled, blockOnLeak: blockOnLeak, rdb: rdb}
}

// Middleware returns HTTP middleware that inspects response bodies.
func (ri *ResponseInspector) Middleware(next http.Handler) http.Handler {
	if !ri.enabled {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cw := &captureResponseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
			body:           &bytes.Buffer{},
			bufferOnly:     ri.blockOnLeak, // if blocking on leak, buffer entire response first
		}

		next.ServeHTTP(cw, r)

		// Inspect the captured response body
		if cw.body != nil && cw.body.Len() > 0 {
			ct := cw.Header().Get("Content-Type")
			if isInspectableContentType(ct) {
				data := cw.body.Bytes()
				if len(data) > maxInspectSize {
					data = data[:maxInspectSize]
				}
				matched := ri.inspectResponse(r, data)

			// If blockOnLeak is enabled and leak detected, replace response with error
			if ri.blockOnLeak && matched {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"success":false,"error":{"code":"RESPONSE_LEAK_BLOCKED","message":"response blocked due to sensitive data leakage"}}`))
				return
			}
			}
		}

		// If we were buffering only, now write the response
		if ri.blockOnLeak && !cw.wroteHeader {
			cw.writeTo(w)
		}
	})
}

func (ri *ResponseInspector) inspectResponse(r *http.Request, body []byte) bool {
	bodyStr := string(body)
	var matched bool

	for _, cat := range inspectPatterns {
		for _, re := range cat.patterns {
			if re.MatchString(bodyStr) {
				log.Printf("response_inspect: %s %s — %s detected (%s)",
					r.Method, r.URL.Path, cat.name, re.String())
				matched = true
				break
			}
		}
	}

	if matched && ri.rdb != nil {
		ri.rdb.Incr(r.Context(), "stats:response_inspect:hits")
	}
	return matched
}

func isInspectableContentType(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.HasPrefix(ct, "text/") ||
		strings.HasPrefix(ct, "application/json") ||
		strings.HasPrefix(ct, "application/xml")
}

type captureResponseWriter struct {
	http.ResponseWriter
	statusCode  int
	body        *bytes.Buffer
	wroteHeader bool
	bufferOnly  bool
}

func (w *captureResponseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.wroteHeader = true
	if !w.bufferOnly {
		w.ResponseWriter.WriteHeader(code)
	}
}

func (w *captureResponseWriter) Write(b []byte) (int, error) {
	// Buffer for inspection (capped)
	if w.body != nil && w.body.Len() < maxInspectSize {
		remaining := maxInspectSize - w.body.Len()
		if len(b) > remaining {
			w.body.Write(b[:remaining])
		} else {
			w.body.Write(b)
		}
	}
	// Forward to client if not buffering only
	if !w.bufferOnly {
		return w.ResponseWriter.Write(b)
	}
	return len(b), nil
}

func (w *captureResponseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *captureResponseWriter) writeTo(target http.ResponseWriter) {
	if w.body != nil && w.body.Len() > 0 {
		target.WriteHeader(w.statusCode)
		target.Write(w.body.Bytes())
	}
}
