package middleware

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/user/waf/internal/logs"
	"github.com/user/waf/internal/replay"
)

// EventSink is a tiny port the middleware uses to publish events
// without depending on a specific transport. main.go wires the
// actual websocket hub into a thin adapter that satisfies this
// interface. Defined here (not in internal/websocket) to break the
// import cycle (hub already imports middleware for request context).
type EventSink interface {
	Emit(event string, data interface{})
}

// RequestLoggingMiddleware logs every request via the async logger.
// Optional geoip parameter enables country lookup for each request.
// Optional replay service stores blocked requests for replay.
// Optional EventSink publishes a `request` event to all Live Feed
// subscribers so the dashboard activity panel reflects traffic in
// real time.
func RequestLoggingMiddleware(logger *logs.Logger, opts ...interface{}) Middleware {
	var geoipChecker *GeoIPChecker
	var replaySvc *replay.Service
	var sink EventSink
	for _, opt := range opts {
		switch v := opt.(type) {
		case *GeoIPChecker:
			geoipChecker = v
		case *replay.Service:
			replaySvc = v
		case EventSink:
			sink = v
		}
	}
	emit := func(event string, payload interface{}) {
		if sink != nil {
			sink.Emit(event, payload)
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ip := extractIP(r)

			// Create shared metrics for this request
			ctx, metrics := NewRequestContext(r.Context())
			r = r.WithContext(ctx)

			// Wrap response writer to capture status
			rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			// Buffer body for replay storage (only if replay service configured)
			var bodyBytes []byte
			if replaySvc != nil && r.Body != nil {
				bodyBytes, _ = io.ReadAll(io.LimitReader(r.Body, 65536))
				r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			}

			next.ServeHTTP(rw, r)

			ipStr := ""
			if ip != nil {
				ipStr = ip.String()
			}

			// GeoIP lookup directly. Private IPs (127.0.0.0/8, 10.0.0.0/8,
			// 192.168.0.0/16, 172.16.0.0/12) are not in the MaxMind DB, so
			// we fall back to "LO" (loopback) or "PR" (private) for them
			// so the dashboard geo-attacks endpoint has a country code to
			// show on the map.
			country := ""
			if ip != nil {
				if ip.IsLoopback() {
					country = "LO"
				} else if isPrivateIP(ip) {
					country = "PR"
				} else if geoipChecker != nil {
					country = geoipChecker.LookupCountry(ip)
				}
			}

			// Read AI classification from metrics (set by AIClassifyMiddleware)
			var scorePtr *float64
			if metrics.AIClassification != "" {
				scorePtr = &metrics.ThreatScore
			}

			action := classifyAction(rw.statusCode)

			logger.Log(logs.RequestLog{
				Timestamp:        start,
				ClientIP:         ipStr,
				Method:           r.Method,
				Host:             r.Host,
				Path:             r.URL.Path,
				Query:            r.URL.RawQuery,
				UserAgent:        r.UserAgent(),
				Action:           action,
				ThreatScore:      scorePtr,
				AIClassification: metrics.AIClassification,
				ResponseCode:     rw.statusCode,
				ResponseTimeMs:   int(time.Since(start).Milliseconds()),
				Country:          country,
				BytesSent:        rw.bytesSent,
				BytesReceived:    r.ContentLength,
			})

			// Broadcast a `request` event to the Live Feed so dashboard
			// subscribers see traffic in real time. We always send
			// (allowed + blocked alike); the panel UI filters by
			// action class on the client side.
			path := r.URL.Path
			if len(path) > 240 {
				path = path[:240]
			}
			emit("request", map[string]interface{}{
				"event":      "request",
				"timestamp":  start.UTC().Format(time.RFC3339Nano),
				"method":     r.Method,
				"path":       path,
				"status":     rw.statusCode,
				"action":     action,
				"client_ip":  ipStr,
				"country":    country,
				"latency_ms": int(time.Since(start).Milliseconds()),
				"ua":         userAgent(r.UserAgent()),
				"threat":     scoreValue(scorePtr),
				"ai_class":   metrics.AIClassification,
			})

			// Store blocked requests for replay
			if replaySvc != nil && action == "blocked" {
				go replaySvc.Store(context.Background(), replay.StoredRequest{
					ClientIP: ipStr,
					Method:   r.Method,
					Host:     r.Host,
					Path:     r.URL.Path,
					Query:    r.URL.RawQuery,
					Headers:  extractHeaders(r),
					Body:     string(bodyBytes),
					Action:   action,
				})
			}
		})
	}
}

type responseWriter struct {
	http.ResponseWriter
	statusCode  int
	bytesSent   int64
	wroteHeader bool
}

func (rw *responseWriter) WriteHeader(code int) {
	if !rw.wroteHeader {
		rw.statusCode = code
		rw.wroteHeader = true
	}
	rw.ResponseWriter.WriteHeader(code)
}

// Write counts bytes written back to the client so the bandwidth
// endpoint can sum bytes_sent per minute bucket. Without this every
// request_logs row reads 0 / 0 and the dashboard Bandwidth chart is
// empty.
func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.bytesSent += int64(n)
	return n, err
}

func (rw *responseWriter) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (rw *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := rw.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("underlying ResponseWriter does not support Hijack")
}

func classifyAction(statusCode int) string {
	if statusCode >= 400 {
		return "blocked"
	}
	return "allowed"
}

// extractHeaders returns key headers for replay storage, redacting sensitive values.
func extractHeaders(r *http.Request) map[string]string {
	headers := make(map[string]string)
	sensitive := map[string]bool{"Authorization": true, "Cookie": true}
	for _, key := range []string{"Content-Type", "Accept", "User-Agent", "Authorization", "Cookie", "Origin", "Referer"} {
		if v := r.Header.Get(key); v != "" {
			if sensitive[key] {
				headers[key] = "[REDACTED]"
			} else {
				headers[key] = v
			}
		}
	}
	return headers
}

// isPrivateIP returns true if ip is in any of the RFC 1918 / RFC 4193
// private-use ranges, link-local, or unique-local IPv6 space. Used to
// give private addresses a visible country code (PR) when no GeoIP DB
// is configured.
func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		// 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
		if ip4[0] == 10 {
			return true
		}
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
		// 169.254.0.0/16 (link-local) and 100.64.0.0/10 (CGN)
		if ip4[0] == 169 && ip4[1] == 254 {
			return true
		}
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return true
		}
	}
	// fc00::/7 unique local
	if len(ip) == 16 && (ip[0]&0xfe) == 0xfc {
		return true
	}
	return false
}

// userAgent returns a short, redacted UA string. We strip the version
// tail of common UAs so the Live Feed row stays compact; full UA is
// already in the request_logs row.
func userAgent(ua string) string {
	ua = strings.TrimSpace(ua)
	if len(ua) > 80 {
		ua = ua[:80] + "…"
	}
	if ua == "" {
		return "-"
	}
	return ua
}

// scoreValue dereferences a possibly-nil threat-score pointer and rounds
// to 2 decimal places for the WebSocket payload.
func scoreValue(p *float64) float64 {
	if p == nil {
		return 0
	}
	v := *p
	if v < 0 {
		return 0
	}
	return float64(int(v*100)) / 100
}
