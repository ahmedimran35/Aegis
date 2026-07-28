package middleware

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// HoneypotTrap handles decoy endpoints to trap attackers.
type HoneypotTrap struct {
	pool   *pgxpool.Pool
	paths  map[string]bool
	enabled bool
}

// NewHoneypotTrap creates a honeypot trap.
func NewHoneypotTrap(pool *pgxpool.Pool, paths []string, enabled bool) *HoneypotTrap {
	pathMap := make(map[string]bool, len(paths))
	for _, p := range paths {
		pathMap[strings.ToLower(p)] = true
	}

	return &HoneypotTrap{
		pool:    pool,
		paths:   pathMap,
		enabled: enabled,
	}
}

// IsHoneypot checks if a path is a honeypot endpoint.
func (h *HoneypotTrap) IsHoneypot(path string) bool {
	if !h.enabled {
		return false
	}
	lower := strings.ToLower(path)
	for hp := range h.paths {
		if strings.HasPrefix(lower, hp) || lower == hp {
			return true
		}
	}
	return false
}

// Trap logs the request and returns a fake response.
func (h *HoneypotTrap) Trap(w http.ResponseWriter, r *http.Request) {
	ip := extractIP(r)
	ipStr := ""
	if ip != nil {
		ipStr = ip.String()
	}

	// Log the trap hit
	log.Printf("HONEYPOT: trapped %s %s from %s (ua: %s)",
		r.Method, sanitizeLog(r.URL.Path), ipStr, sanitizeLog(r.UserAgent()))

	// Store in database
	go h.storeHit(r, ipStr)

	// Return a fake response that looks real
	h.fakeResponse(w, r)
}

func (h *HoneypotTrap) storeHit(r *http.Request, ipStr string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Collect headers
	headers := make(map[string][]string)
	for k, v := range r.Header {
		headers[k] = v
	}
	headersJSON, _ := json.Marshal(headers)

	// Read body
	body := readBody(r)

	_, err := h.pool.Exec(ctx,
		`INSERT INTO honeypot_hits (client_ip, method, path, query, headers, body, user_agent)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		ipStr, r.Method, r.URL.Path, r.URL.RawQuery, headersJSON, body, r.UserAgent())
	if err != nil {
		log.Printf("honeypot: store: %v", err)
	}
}

func (h *HoneypotTrap) fakeResponse(w http.ResponseWriter, r *http.Request) {
	path := strings.ToLower(r.URL.Path)

	switch {
	case strings.Contains(path, "admin") || strings.Contains(path, "login"):
		// Fake login page
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		w.Write([]byte(`<!DOCTYPE html><html><head><title>Admin Login</title></head>
		<body><h1>Administration Panel</h1>
		<form method="POST"><input name="user" placeholder="Username"><input name="pass" type="password">
		<button type="submit">Login</button></form></body></html>`))

	case strings.Contains(path, ".env"):
		// Fake env file - obviously fake values to prevent credential leakage if indexed
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		w.Write([]byte(`# Environment Configuration (HONEYPOT - FAKE VALUES)
APP_NAME=HoneypotApp
APP_ENV=honeypot
DB_HOST=127.0.0.1
DB_PORT=5432
DB_DATABASE=honeypot_db
DB_USERNAME=honeypot_user
DB_PASSWORD=HONEYPOT_FAKE_PASSWORD_DO_NOT_USE
CACHE_DRIVER=redis
SESSION_DRIVER=file
MAIL_HOST=smtp.honeypot.local
MAIL_PORT=587
# THIS IS A HONEYPOT TRAP - ALL VALUES ARE FAKE
`))

	case strings.Contains(path, "phpmyadmin") || strings.Contains(path, "pma"):
		// Fake phpMyAdmin
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		w.Write([]byte(`<!DOCTYPE html><html><head><title>phpMyAdmin</title></head>
		<body><h1>phpMyAdmin 4.9.7</h1><form>Server: <input><br>User: <input><br>
		Password: <input type="password"><br><button>Login</button></form></body></html>`))

	case strings.Contains(path, "wp-login"):
		// Fake WordPress login
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		w.Write([]byte(`<!DOCTYPE html><html><head><title>Log In ‹ WordPress</title></head>
		<body><form name="loginform" method="post">
		<label>Username or Email Address</label><input name="log" type="text">
		<label>Password</label><input name="pwd" type="password">
		<input type="submit" name="wp-submit" value="Log In"></form></body></html>`))

	case strings.Contains(path, "xmlrpc"):
		// Fake XML-RPC
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(200)
		w.Write([]byte(`<?xml version="1.0"?><methodResponse><fault><value><struct>
		<member><name>faultCode</name><value><int>403</int></value></member>
		<member><name>faultString</name><value><string>XML-RPC services are disabled.</string></value></member>
		</struct></value></fault></methodResponse>`))

	default:
		// Generic fake page
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(404)
		w.Write([]byte(`<!DOCTYPE html><html><head><title>404 Not Found</title></head>
		<body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>`))
	}
}

// Middleware returns honeypot middleware that intercepts trap paths.
func (h *HoneypotTrap) Middleware(next http.Handler) http.Handler {
	if !h.enabled {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.IsHoneypot(r.URL.Path) {
			h.Trap(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// GetHits returns recent honeypot hits.
func (h *HoneypotTrap) GetHits(ctx context.Context, page, perPage int) ([]map[string]interface{}, int, error) {
	offset := (page - 1) * perPage

	var total int
	err := h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM honeypot_hits`).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	rows, err := h.pool.Query(ctx,
		`SELECT id, client_ip, method, path, query, user_agent, created_at
		 FROM honeypot_hits ORDER BY created_at DESC LIMIT $1 OFFSET $2`, perPage, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var hits []map[string]interface{}
	for rows.Next() {
		var id int64
		var ip, method, path, ua string
		var query *string
		var createdAt time.Time

		if err := rows.Scan(&id, &ip, &method, &path, &query, &ua, &createdAt); err != nil {
			continue
		}

		hit := map[string]interface{}{
			"id":         id,
			"client_ip":  ip,
			"method":     method,
			"path":       path,
			"user_agent": ua,
			"created_at": createdAt,
		}
		if query != nil {
			hit["query"] = *query
		}
		hits = append(hits, hit)
	}

	return hits, total, nil
}

// GetStats returns honeypot statistics.
func (h *HoneypotTrap) GetStats(ctx context.Context) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Total hits
	var totalHits int
	if err := h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM honeypot_hits`).Scan(&totalHits); err != nil {
		log.Printf("honeypot stats: scan: %v", err)
	}
	stats["total_hits"] = totalHits

	// Hits today
	var todayHits int
	if err := h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM honeypot_hits WHERE created_at > NOW() - INTERVAL '24 hours'`).Scan(&todayHits); err != nil {
		log.Printf("honeypot stats: scan: %v", err)
	}
	stats["hits_today"] = todayHits

	// Top attacker IPs
	rows, err := h.pool.Query(ctx,
		`SELECT client_ip, COUNT(*) as cnt FROM honeypot_hits
		 WHERE created_at > NOW() - INTERVAL '24 hours'
		 GROUP BY client_ip ORDER BY cnt DESC LIMIT 10`)
	if err == nil {
		defer rows.Close()
		var topIPs []map[string]interface{}
		for rows.Next() {
			var ip string
			var cnt int
			rows.Scan(&ip, &cnt)
			topIPs = append(topIPs, map[string]interface{}{"ip": ip, "hits": cnt})
		}
		stats["top_attackers"] = topIPs
	}

	// Top paths
	rows, err = h.pool.Query(ctx,
		`SELECT path, COUNT(*) as cnt FROM honeypot_hits
		 WHERE created_at > NOW() - INTERVAL '24 hours'
		 GROUP BY path ORDER BY cnt DESC LIMIT 10`)
	if err == nil {
		defer rows.Close()
		var topPaths []map[string]interface{}
		for rows.Next() {
			var path string
			var cnt int
			rows.Scan(&path, &cnt)
			topPaths = append(topPaths, map[string]interface{}{"path": path, "hits": cnt})
		}
		stats["top_paths"] = topPaths
	}

	return stats, nil
}
