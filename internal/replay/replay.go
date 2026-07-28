package replay

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// StoredRequest holds a captured request for replay.
type StoredRequest struct {
	ID        int64             `json:"id"`
	ClientIP  string            `json:"client_ip"`
	Method    string            `json:"method"`
	Host      string            `json:"host"`
	Path      string            `json:"path"`
	Query     string            `json:"query"`
	Headers   map[string]string `json:"headers,omitempty"`
	Body      string            `json:"body,omitempty"`
	Action    string            `json:"action"`
	RuleID    int               `json:"rule_id,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
}

// ReplayResult holds the outcome of a replay.
type ReplayResult struct {
	Success      bool   `json:"success"`
	StatusCode   int    `json:"status_code,omitempty"`
	Response     string `json:"response,omitempty"`
	ResponseTime int64  `json:"response_time_ms,omitempty"`
	Error        string `json:"error,omitempty"`
}

// Service manages stored requests for replay.
type Service struct {
	pool        *pgxpool.Pool
	upstreamURL string
}

// NewService creates a replay service.
func NewService(pool *pgxpool.Pool, upstreamURL string) *Service {
	return &Service{pool: pool, upstreamURL: upstreamURL}
}

// List returns stored requests with pagination.
func (s *Service) List(ctx context.Context, page, perPage int) ([]StoredRequest, int, error) {
	offset := (page - 1) * perPage

	var total int
	err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM request_replay`).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	rows, err := s.pool.Query(ctx,
		`SELECT id, client_ip::text, method, host, path, query, body, action, rule_id, created_at
		 FROM request_replay ORDER BY created_at DESC LIMIT $1 OFFSET $2`, perPage, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var requests []StoredRequest
	for rows.Next() {
		var req StoredRequest
		var body *string
		if err := rows.Scan(&req.ID, &req.ClientIP, &req.Method, &req.Host, &req.Path,
			&req.Query, &body, &req.Action, &req.RuleID, &req.CreatedAt); err != nil {
			continue
		}
		if body != nil {
			req.Body = *body
		}
		requests = append(requests, req)
	}

	return requests, total, nil
}

// Get returns a single stored request.
func (s *Service) Get(ctx context.Context, id int64) (*StoredRequest, error) {
	var req StoredRequest
	var body *string
	err := s.pool.QueryRow(ctx,
		`SELECT id, client_ip::text, method, host, path, query, body, action, rule_id, created_at
		 FROM request_replay WHERE id = $1`, id).Scan(
		&req.ID, &req.ClientIP, &req.Method, &req.Host, &req.Path,
		&req.Query, &body, &req.Action, &req.RuleID, &req.CreatedAt)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Body = *body
	}
	return &req, nil
}

// Replay sends a stored request to the upstream.
// pinnedIP is the pre-resolved IP address (from validation) to prevent DNS rebinding.
// hostname is the original hostname for Host header virtual hosting.
func (s *Service) Replay(ctx context.Context, id int64, targetURL, pinnedIP, hostname string) (*ReplayResult, error) {
	req, err := s.Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get request: %w", err)
	}

	upstream := targetURL
	if upstream == "" {
		upstream = s.upstreamURL
	}

	// P-FIX (CWE-918): SSRF allowlist. Without this check, an analyst with
	// /api/v1/replay access could pivot the WAF into sending requests to
	// arbitrary targets (internal admin panels, cloud metadata endpoints,
	// external hosts under attacker control). If the operator has set
	// AEGIS_REPLAY_ALLOWED_HOSTS, only those hosts are accepted. Otherwise
	// we fall back to the configured upstreamURL host as the single
	// permitted target.
	if err := s.validateReplayTarget(upstream); err != nil {
		return nil, fmt.Errorf("replay target rejected: %w", err)
	}

	replayURL := upstream + req.Path
	if req.Query != "" {
		replayURL += "?" + req.Query
	}

	var bodyReader io.Reader
	if req.Body != "" {
		bodyReader = bytes.NewReader([]byte(req.Body))
	}

	httpReq, err := http.NewRequestWithContext(ctx, req.Method, replayURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("X-Aegis-Replay", "true")
	httpReq.Header.Set("X-Aegis-Original-IP", req.ClientIP)
	if hostname != "" {
		httpReq.Host = hostname
	}

	start := time.Now()

	// Build transport: if pinnedIP is set, use custom dialer to prevent DNS rebinding
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if pinnedIP != "" {
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				port = "80"
			}
			dialer := &net.Dialer{}
			return dialer.DialContext(ctx, network, net.JoinHostPort(pinnedIP, port))
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		log.Printf("replay: request failed: %v", err)
		return &ReplayResult{
			Success:      false,
			Error:        "replay request failed",
			ResponseTime: time.Since(start).Milliseconds(),
		}, nil
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 10240))

	return &ReplayResult{
		Success:      true,
		StatusCode:   resp.StatusCode,
		Response:     string(respBody),
		ResponseTime: time.Since(start).Milliseconds(),
	}, nil
}

// Store saves a request for replay.
func (s *Service) Store(ctx context.Context, req StoredRequest) error {
	headersJSON, _ := json.Marshal(req.Headers)
	_, err := s.pool.Exec(ctx,
		`INSERT INTO request_replay (client_ip, method, host, path, query, headers, body, action, rule_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		req.ClientIP, req.Method, req.Host, req.Path, req.Query,
		string(headersJSON), req.Body, req.Action, req.RuleID)
	return err
}

// Delete removes a stored request.
func (s *Service) Delete(ctx context.Context, id int64) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM request_replay WHERE id = $1`, id)
	return err
}

// validateReplayTarget returns nil if the replay target is permitted.
// The allowlist is sourced from AEGIS_REPLAY_ALLOWED_HOSTS (comma-separated
// host:port list). If unset, the configured upstreamURL host is the only
// permitted target — analyst users cannot pivot the WAF elsewhere.
func (s *Service) validateReplayTarget(rawURL string) error {
	if rawURL == "" {
		return fmt.Errorf("empty target")
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid target URL")
	}
	target := strings.ToLower(u.Host)

	allowed := os.Getenv("AEGIS_REPLAY_ALLOWED_HOSTS")
	if allowed != "" {
		for _, h := range strings.Split(allowed, ",") {
			h = strings.TrimSpace(strings.ToLower(h))
			if h == "" {
				continue
			}
			if h == target {
				return nil
			}
		}
		return fmt.Errorf("target %q not in AEGIS_REPLAY_ALLOWED_HOSTS", target)
	}

	// No explicit allowlist: only the configured upstream host is allowed.
	if s.upstreamURL == "" {
		return fmt.Errorf("no upstream configured and no allowlist set")
	}
	up, err := url.Parse(s.upstreamURL)
	if err != nil || up.Host == "" {
		return fmt.Errorf("configured upstream is invalid")
	}
	if strings.ToLower(up.Host) != target {
		return fmt.Errorf("target %q does not match configured upstream %q (set AEGIS_REPLAY_ALLOWED_HOSTS to expand)", target, up.Host)
	}
	return nil
}
