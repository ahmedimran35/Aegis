package middleware

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Canary is a middleware that detects access to "canary" tokens —
// invisible form fields, trap URLs, ghost cookies, fake headers — that
// any automated attacker / scraper will hit while a real human never
// will. On a hit, records the request and returns 403.
//
// Tokens are loaded from the canary_tokens table at start and refreshed
// every 60 s, so adding a canary via the admin API takes effect within
// a minute without a restart.
type Canary struct {
	pool *pgxpool.Pool

	mu   sync.RWMutex
	toks map[string]canaryRow // token_value -> row
}

type canaryRow struct {
	id         int
	name       string
	kind       string
	placement  string
}

// NewCanary creates a Canary detector. pool may be nil for tests.
func NewCanary(pool *pgxpool.Pool) *Canary {
	c := &Canary{pool: pool, toks: map[string]canaryRow{}}
	if pool != nil {
		_ = c.refresh(context.Background())
		go c.refresher()
	}
	return c
}

// Refresh reloads the in-memory token cache from the DB on demand.
// Public so admin handlers can force a refresh after mutating tokens.
func (c *Canary) Refresh(ctx context.Context) error { return c.refresh(ctx) }

func (c *Canary) refresher() {
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for range t.C {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = c.refresh(ctx)
		cancel()
	}
}

func (c *Canary) refresh(ctx context.Context) error {
	if c.pool == nil {
		return nil
	}
	rows, err := c.pool.Query(ctx, `SELECT id, name, kind, placement, token_value FROM canary_tokens WHERE enabled = true`)
	if err != nil {
		return err
	}
	defer rows.Close()
	m := map[string]canaryRow{}
	for rows.Next() {
		var r canaryRow
		var tv string
		if err := rows.Scan(&r.id, &r.name, &r.kind, &r.placement, &tv); err == nil {
			m[tv] = r
		}
	}
	c.mu.Lock()
	c.toks = m
	c.mu.Unlock()
	return nil
}

// Middleware scans incoming requests for known canary token values in
// the URL, body, headers, or cookies. A hit returns 403 and records
// the event in canary_hits.
func (c *Canary) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c == nil || c.pool == nil {
			next.ServeHTTP(w, r)
			return
		}

		matched, where, foundVal := c.scan(r)
		if matched == 0 {
			next.ServeHTTP(w, r)
			return
		}

		// Record the hit. Best-effort; do not block the response on it.
		// Use a fresh background context — r.Context() is already cancelled
		// by the time the response goes out, which would fail the INSERT.
		go c.record(context.Background(), matched, where, foundVal, r)

		// Return 403 to the client and short-circuit.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"success":false,"error":{"code":"CANARY_TRIPPED","message":"forbidden - canary token detected"}}`))
	})
}

func (c *Canary) scan(r *http.Request) (int, string, string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.toks) == 0 {
		return 0, "", ""
	}
	// 1) URL path
	for tok, row := range c.toks {
		if strings.Contains(r.URL.Path, tok) {
			return row.id, "path:" + row.placement, tok
		}
	}
	// 2) query
	if r.URL.RawQuery != "" {
		for tok, row := range c.toks {
			if strings.Contains(r.URL.RawQuery, tok) {
				return row.id, "query:" + row.placement, tok
			}
		}
	}
	// 3) headers
	for tok, row := range c.toks {
		for _, hdr := range r.Header {
			if len(hdr) == 0 {
				continue
			}
			h := strings.Join(hdr, ",")
			if strings.Contains(h, tok) {
				return row.id, "header:" + row.placement, tok
			}
		}
	}
	// 4) cookies
	for _, c2 := range r.Cookies() {
		for tok, row := range c.toks {
			if strings.Contains(c2.Value, tok) {
				return row.id, "cookie:" + row.placement, tok
			}
		}
	}
	// 5) body (peek, no consumption)
	if r.Body != nil && r.ContentLength > 0 && r.ContentLength < 1<<20 {
		body, _ := io.ReadAll(io.LimitReader(r.Body, r.ContentLength))
		r.Body = io.NopCloser(bytes.NewReader(body))
		for tok, row := range c.toks {
			if bytes.Contains(body, []byte(tok)) {
				return row.id, "body:" + row.placement, tok
			}
		}
	}
	return 0, "", ""
}

func (c *Canary) record(ctx context.Context, tokenID int, where, foundVal string, r *http.Request) {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	ua := r.UserAgent()
	var excerpt string
	if r.ContentLength > 0 && r.ContentLength < 4096 {
		if body, _ := io.ReadAll(io.LimitReader(r.Body, int64(r.ContentLength))); len(body) > 0 {
			excerpt = string(body)
		}
	}
	_, _ = c.pool.Exec(ctx,
		`INSERT INTO canary_hits (token_id, ip, method, path, user_agent, matched_on, request_excerpt)
		 VALUES ($1, NULLIF($2,'')::inet, $3, $4, $5, $6, NULLIF($7, ''))`,
		tokenID, ip, r.Method, r.URL.Path, ua, where, excerpt,
	)
}

// GenerateToken is a helper for the admin handler to issue cryptographically
// random canary values.
func GenerateToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return "aegis-canary-" + hex.EncodeToString(b)
}
