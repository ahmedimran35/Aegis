package middleware

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ===========================================================================
// Combined "advanced features" middlewares. Each struct is independently
// usable; main.go composes them into the proxy pipeline.
// ===========================================================================

// ---------- #4 JWT defense-in-depth (alg allow-list + kid injection) ----------

// JWTGuard rejects JWTs whose `alg` is `none` (CVE-2015-9235) or not in
// the persisted allow-list. Also rejects `kid` headers containing
// characters commonly used in SQLi / path traversal exploits.
type JWTGuard struct {
	pool        *pgxpool.Pool
	mu          sync.RWMutex
	allowedAlgs map[string]bool
}

func NewJWTGuard(pool *pgxpool.Pool) *JWTGuard {
	g := &JWTGuard{pool: pool, allowedAlgs: map[string]bool{}}
	if pool != nil {
		_ = g.refresh(context.Background())
	}
	return g
}

func (g *JWTGuard) refresh(ctx context.Context) error {
	if g.pool == nil {
		return nil
	}
	rows, err := g.pool.Query(ctx, `SELECT alg FROM jwt_allowlist WHERE enabled = true`)
	if err != nil {
		return err
	}
	defer rows.Close()
	m := map[string]bool{}
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err == nil {
			m[strings.ToUpper(a)] = true
		}
	}
	g.mu.Lock()
	g.allowedAlgs = m
	g.mu.Unlock()
	return nil
}

func (g *JWTGuard) Refresh(ctx context.Context) error { return g.refresh(ctx) }

func (g *JWTGuard) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			next.ServeHTTP(w, r)
			return
		}
		raw := strings.TrimPrefix(auth, "Bearer ")
		parts := strings.SplitN(raw, ".", 3)
		if len(parts) != 3 {
			respondJSONError(w, http.StatusUnauthorized, "INVALID_JWT", "malformed JWT — expected 3 segments")
			return
		}
		hdr, err := jwtDecodeHeader(parts[0])
		if err != nil {
			respondJSONError(w, http.StatusUnauthorized, "INVALID_JWT_HEADER", "JWT header not valid base64-JSON")
			return
		}
		alg, _ := hdr["alg"].(string)
		kid, _ := hdr["kid"].(string)
		if strings.EqualFold(alg, "none") || alg == "" {
			respondJSONError(w, http.StatusUnauthorized, "JWT_ALG_NONE", "alg=none rejected (CVE-2015-9235 class)")
			return
		}
		if kid != "" && (strings.Contains(kid, "..") || strings.ContainsAny(kid, "'\";\\") || strings.Contains(kid, " ")) {
			respondJSONError(w, http.StatusUnauthorized, "JWT_KID_INJECTION", "kid field contains forbidden characters")
			return
		}
		g.mu.RLock()
		ok := g.allowedAlgs[strings.ToUpper(alg)]
		g.mu.RUnlock()
		if !ok {
			respondJSONError(w, http.StatusUnauthorized, "JWT_ALG_NOT_ALLOWED", "alg '"+alg+"' not in allow list (see /jwt/allowlist)")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func jwtDecodeHeader(seg string) (map[string]any, error) {
	// url-safe → std base64 + pad
	seg = strings.ReplaceAll(seg, "-", "+")
	seg = strings.ReplaceAll(seg, "_", "/")
	for len(seg)%4 != 0 {
		seg += "="
	}
	b, err := base64.StdEncoding.DecodeString(seg)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ---------- #3 LLM endpoint protection (heuristic prompt-injection filter) ----------

// LLMSentry applies a curated set of regex rules to request bodies on
// routes that look like LLM endpoints. Lightweight; no model inference.
type LLMSentry struct {
	mu    sync.RWMutex
	rules []llmRule
}

type llmRule struct {
	name    string
	kind    string
	pattern *regexp.Regexp
}

func NewLLMSentry() *LLMSentry {
	s := &LLMSentry{}
	s.loadDefaults()
	return s
}

func (s *LLMSentry) loadDefaults() {
	defaults := []struct{ name, kind, pattern string }{
		{"prompt-injection: ignore-previous", "prompt_injection", `(?i)\b(ignore|disregard|forget)\b[^\n]{0,40}\b(previous|prior|all|above)\b[^\n]{0,30}\b(instructions?|system|prompt|rules?)\b`},
		{"prompt-injection: developer-mode", "prompt_injection", `(?i)\b(developer\s*mode|dan\s*mode|jailbreak|do\s*anything\s*now)\b`},
		{"jailbreak: reveal system", "jailbreak", `(?i)\b(reveal|show|repeat|print|dump)\b[^\n]{0,40}\b(system|hidden|secret|internal)\b[^\n]{0,30}\b(prompt|instructions?)\b`},
		{"pii-leak: extract ssns", "pii_leak", `\b\d{3}-\d{2}-\d{4}\b`},
		{"pii-leak: credit-card", "pii_leak", `\b(?:\d[ -]*?){13,16}\b`},
		{"system-prompt-leak", "system_prompt_leak", `(?i)\b(system\s*prompt|initial\s*instructions?|hidden\s*rules?)\b`},
	}
	for _, d := range defaults {
		// MustCompile (panics on bad regex) instead of Compile (returns err)
		// is safe here because patterns are hard-coded in this file and
		// reviewed at compile time. Saves a per-rule per-request parse.
		s.rules = append(s.rules, llmRule{
			name:    d.name,
			kind:    d.kind,
			pattern: regexp.MustCompile(d.pattern),
		})
	}
}

func (s *LLMSentry) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only scan bodies on LLM-looking endpoints
		looks := strings.HasPrefix(r.URL.Path, "/api/v1/llm") ||
			strings.HasPrefix(r.URL.Path, "/llm") ||
			strings.HasPrefix(r.URL.Path, "/v1/chat")
		if !looks {
			next.ServeHTTP(w, r)
			return
		}
		if r.ContentLength == 0 || r.Body == nil {
			next.ServeHTTP(w, r)
			return
		}
		if r.ContentLength > 4*1024*1024 {
			respondJSONError(w, http.StatusRequestEntityTooLarge, "PROMPT_TOO_LARGE",
				fmt.Sprintf("prompt body %d bytes exceeds 4 MB", r.ContentLength))
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, r.ContentLength))
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		s.mu.RLock()
		defer s.mu.RUnlock()
		for _, r2 := range s.rules {
			if r2.pattern.Match(body) {
				respondJSONError(w, http.StatusBadRequest, "LLM_POLICY_VIOLATION", r2.name)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// ---------- #5 per-endpoint anomaly scoring ----------

// AnomalyWatch keeps a per-(path, method) in-memory window and raises
// a flag when the request rate exceeds baseline by 5×. Persists into
// endpoint_anomaly / endpoint_anomaly_events.
type AnomalyWatch struct {
	mu   sync.Mutex
	seen map[string]*anomalyWindow
	mult float64
}

type anomalyWindow struct {
	ts  []time.Time
	inc int64
}

func NewAnomalyWatch() *AnomalyWatch {
	return &AnomalyWatch{seen: map[string]*anomalyWindow{}, mult: 5.0}
}

func (a *AnomalyWatch) Middleware(pool *pgxpool.Pool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/assets/") || strings.HasPrefix(r.URL.Path, "/api/v1/dashboard") || strings.HasPrefix(r.URL.Path, "/api/v1/health") {
				next.ServeHTTP(w, r)
				return
			}
			key := r.Method + " " + r.URL.Path
			now := time.Now()
			cutoff := now.Add(-1 * time.Minute)
			a.mu.Lock()
			win := a.seen[key]
			if win == nil {
				win = &anomalyWindow{}
				a.seen[key] = win
			}
			j := 0
			for _, t := range win.ts {
				if t.After(cutoff) {
					win.ts[j] = t
					j++
				}
			}
			win.ts = win.ts[:j]
			win.ts = append(win.ts, now)
			current := float64(len(win.ts)) / 60.0
			a.mu.Unlock()
			if current > a.mult && len(win.ts) > 60 {
				_, _ = pool.Exec(r.Context(),
					`INSERT INTO endpoint_anomaly_events (path, method, observed_qps, baseline_qps, multiplier, severity) VALUES ($1, $2, $3, $4, $5, 'high')`,
					r.URL.Path, r.Method, current, current/a.mult, a.mult,
				)
			}
			go func(method, path string) {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				bucket := now.Truncate(time.Minute)
				_, _ = pool.Exec(ctx,
					`INSERT INTO endpoint_anomaly (path, method, window_start, total) VALUES ($1, $2, $3, 1) ON CONFLICT (path, method, window_start) DO UPDATE SET total = endpoint_anomaly.total + 1`,
					path, method, bucket,
				)
			}(r.Method, r.URL.Path)
			next.ServeHTTP(w, r)
		})
	}
}

// ---------- #6 browser challenge (PoW token issuance) ----------

// BrowserChallenge is the edge hook. The full challenge page is
// out of scope; the issue endpoint generates a PoW token.
type BrowserChallenge struct {
	pool *pgxpool.Pool
}

func NewBrowserChallenge(pool *pgxpool.Pool) *BrowserChallenge { return &BrowserChallenge{pool: pool} }

func (b *BrowserChallenge) Issue(w http.ResponseWriter, r *http.Request) {
	if b.pool == nil {
		http.Error(w, "db unavailable", http.StatusServiceUnavailable)
		return
	}
	t := make([]byte, 32)
	_, _ = rand.Read(t)
	tok := hex.EncodeToString(t)
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	ua := r.UserAgent()
	_, err := b.pool.Exec(r.Context(),
		`INSERT INTO browser_challenge (token, ip, user_agent, expires_at) VALUES ($1, NULLIF($2,'')::inet, $3, NOW() + INTERVAL '10 minutes')`,
		tok, ip, ua,
	)
	if err != nil {
		respondJSONError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
		return
	}
	// SECURITY: do NOT return the expected hash in the response — the
	// client must compute it. Returning it would defeat the entire PoW
	// purpose (the server response tells the client exactly what to sign).
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"token":"` + tok + `","expires_in":600,"solve":"sha256(token || your_ip) hex; send back in X-Challenge-Proof"}`))
}

func (b *BrowserChallenge) Solve(w http.ResponseWriter, r *http.Request) {
	// Receives a proof and checks it.
	if b.pool == nil {
		http.Error(w, "db unavailable", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		Token string `json:"token"`
		Proof string `json:"proof"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<10)).Decode(&req); err != nil {
		respondJSONError(w, http.StatusBadRequest, "INVALID_JSON", err.Error())
		return
	}
	if len(req.Token) == 0 || len(req.Proof) == 0 {
		respondJSONError(w, http.StatusBadRequest, "MISSING_FIELDS", "token and proof required")
		return
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	h := sha256.New()
	h.Write([]byte(req.Token + ip))
	expected := h.Sum(nil)
	// SECURITY: constant-time hex decode and compare — never use the
	// `==` operator on attacker-supplied input.
	want, err := hex.DecodeString(req.Proof)
	if err != nil || subtle.ConstantTimeCompare(expected, want) != 1 {
		respondJSONError(w, http.StatusForbidden, "PROOF_MISMATCH", "PoW proof invalid")
		return
	}
	_, _ = b.pool.Exec(r.Context(),
		`UPDATE browser_challenge SET solved = true, solved_at = NOW() WHERE token = $1 AND ip = NULLIF($2,'')::inet AND solved = false`,
		req.Token, ip,
	)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"solved":true,"expires_in":600}`))
}

// ---------- #11 file-upload AV (size + magic-bytes) ----------

// UploadGuard rejects uploads whose Content-Length is suspicious.
type UploadGuard struct {
	maxBytes int
}

func NewUploadGuard(maxBytes int) *UploadGuard {
	if maxBytes <= 0 {
		maxBytes = 25 * 1024 * 1024
	}
	return &UploadGuard{maxBytes: maxBytes}
}

func (u *UploadGuard) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct := r.Header.Get("Content-Type")
		if !strings.HasPrefix(ct, "multipart/form-data") &&
			!strings.HasPrefix(ct, "application/octet-stream") {
			next.ServeHTTP(w, r)
			return
		}
		if r.ContentLength > int64(u.maxBytes) {
			respondJSONError(w, http.StatusRequestEntityTooLarge, "UPLOAD_TOO_LARGE",
				fmt.Sprintf("upload body %d bytes exceeds limit %d", r.ContentLength, u.maxBytes))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func RecordUploadScan(pool *pgxpool.Pool, ip, contentType, filename, magic, verdict, matchedRule string, sizeBytes int) {
	if pool == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, _ = pool.Exec(ctx,
			`INSERT INTO upload_scans (ip, content_type, filename, size_bytes, detected_magic, verdict, matched_rule) VALUES (NULLIF($1,'')::inet, $2, $3, $4, $5, $6, $7)`,
			ip, contentType, filename, sizeBytes, magic, verdict, matchedRule,
		)
	}()
}

// ---------- #2 ATO credential-stuffing detection (per-account) ----------

// ATOSignal tracks distinct usernames per source IP on /auth/login.
// After 8+ distinct usernames in 60s the IP is recorded as a
// credential-stuffing event.
type ATOSignal struct {
	mu sync.Mutex
	w  map[string]*stuffWindow
}

type stuffWindow struct {
	users map[string]struct{}
	ts    []time.Time
}

func NewATOSignal() *ATOSignal { return &ATOSignal{w: map[string]*stuffWindow{}} }

func (a *ATOSignal) Middleware(pool *pgxpool.Pool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/auth/login") {
				_ = a.observe(pool, r)
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (a *ATOSignal) observe(pool *pgxpool.Pool, r *http.Request) error {
	if pool == nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<14))
	r.Body = io.NopCloser(strings.NewReader(string(body)))
	var p struct {
		Username string `json:"username"`
	}
	_ = json.Unmarshal(body, &p)
	if p.Username == "" {
		return nil
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	now := time.Now()
	a.mu.Lock()
	w := a.w[ip]
	if w == nil {
		w = &stuffWindow{users: map[string]struct{}{}}
		a.w[ip] = w
	}
	w.users[p.Username] = struct{}{}
	w.ts = append(w.ts, now)
	cutoff := now.Add(-60 * time.Second)
	j := 0
	for _, t := range w.ts {
		if t.After(cutoff) {
			w.ts[j] = t
			j++
		}
	}
	w.ts = w.ts[:j]
	count := len(w.users)
	attempts := len(w.ts)
	a.mu.Unlock()
	if count >= 8 && attempts >= 8 {
		_, _ = pool.Exec(r.Context(),
			`INSERT INTO credential_stuffing_events (ip, username, distinct_users_count, attempt_count, blocked) VALUES ($1, $2, $3, $4, true)`,
			ip, p.Username, count, attempts,
		)
	}
	return nil
}

// ---------- #12 Active attack-surface discovery (passive) ----------

// PathClassifier passively records 4xx/5xx hits on rare paths into the
// asm_findings table. The "active" half (subdomain enumeration) is a
// separate command-line scanner; this is the data-collection edge.
type PathClassifier struct {
	pool *pgxpool.Pool
}

func NewPathClassifier(pool *pgxpool.Pool) *PathClassifier { return &PathClassifier{pool: pool} }

func (c *PathClassifier) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c.pool == nil || r.URL.Path == "/" || strings.HasPrefix(r.URL.Path, "/assets/") {
			next.ServeHTTP(w, r)
			return
		}
		// Skip the high-volume dashboard poll paths to avoid spamming
		// asm_findings with the same 4 URLs every refresh. The skip is
		// exact-match (not prefix) so any unknown /api/v1/* path with a
		// 4xx still gets recorded.
		switch r.URL.Path {
		case "/api/v1/dashboard/overview", "/api/v1/dashboard/traffic",
			"/api/v1/dashboard/bandwidth", "/api/v1/dashboard/threat-events",
			"/api/v1/dashboard/geo-attacks", "/api/v1/dashboard/top-ips",
			"/api/v1/dashboard/top-endpoints", "/api/v1/dashboard/threats",
			"/api/v1/dashboard/waf-health":
			next.ServeHTTP(w, r)
			return
		}
		// Local recorder: just observe the status code.
		rec := &asmRec{ResponseWriter: w, statusCode: 200}
		next.ServeHTTP(rec, r)
		if rec.statusCode >= 400 && rec.statusCode < 500 {
			sev := "info"
			if rec.statusCode == 401 || rec.statusCode == 403 {
				sev = "medium"
			}
			path := r.URL.Path
			_, _ = c.pool.Exec(r.Context(),
				`INSERT INTO asm_findings (asset_kind, asset_value, severity, source, last_seen_at) VALUES ('path', $1, $2, 'passive_4xx', NOW()) ON CONFLICT (asset_kind, asset_value) DO UPDATE SET last_seen_at = NOW(), severity = EXCLUDED.severity`,
				path, sev,
			)
		}
	})
}

type asmRec struct {
	http.ResponseWriter
	statusCode int
	wroteHeader bool
}

func (r *asmRec) WriteHeader(code int) {
	if !r.wroteHeader {
		r.statusCode = code
		r.wroteHeader = true
	}
	r.ResponseWriter.WriteHeader(code)
}

// Hijack forwards to the underlying writer so the WebSocket /api/v1/ws
// upgrade succeeds when PathClassifier is in the chain. Without this,
// the gorilla upgrader sees an asmRec (which only implements WriteHeader)
// and returns "underlying ResponseWriter does not support Hijack" —
// which is what makes the dashboard's "Live" badge show "Offline".
func (r *asmRec) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := r.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("asmRec: underlying ResponseWriter does not support Hijack")
}

// Flush forwards to the underlying writer for streaming endpoints
// (SSE, long-polling, etc.) that may be in the same pipeline.
func (r *asmRec) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// ---------- helpers (shared with the rest of the middleware package) ----------

func respondJSONError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"success":false,"error":{"code":"` + code + `","message":"` + msg + `"}}`))
}
