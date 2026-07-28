package middleware

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"

	"github.com/user/waf/internal/audit"
)

// ============================================================================
// GRPCInspect — L7 frame parser for HTTP/2 cleartext (h2c) and gRPC traffic.
//
// Goals:
//   1. Reject malformed gRPC frames (oversized, non-UTF-8 path, bad
//      pseudo-headers, non-gRPC content-type).
//   2. Reject mTLS-bypass attempts: HTTP/1.1 Upgrade: h2c and CONNECT
//      tunneling are common ways to skip TLS. We reject both.
//   3. Enforce a per-message size cap (default 4 MB; matches the
//      global request body cap).
//   4. Validate gRPC path shape: must be `/<package>.<Service>/<Method>`.
//
// Detection: triggers only on requests that look like gRPC —
//   Content-Type: application/grpc OR
//   POST /<Service>/<Method>.
// ============================================================================

const (
	grpcMaxBodyBytes = 4 * 1024 * 1024
	grpcMaxPathBytes = 256
	grpcContentType  = "application/grpc"
)

var (
	grpcMethodRE = regexp.MustCompile(`^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+){1,5}/[A-Za-z0-9_]{1,64}$`)
	grpcProtoRE  = regexp.MustCompile(`^[A-Za-z0-9_\-]+(?:\.[A-Za-z0-9_\-]+){0,5}$`)
)

type GRPCInspect struct {
	maxBodyBytes int
	audit        *audit.Logger
}

func NewGRPCInspect(maxBodyBytes int, al *audit.Logger) *GRPCInspect {
	if maxBodyBytes <= 0 {
		maxBodyBytes = grpcMaxBodyBytes
	}
	return &GRPCInspect{maxBodyBytes: maxBodyBytes, audit: al}
}

// Middleware inspects every request; bails out fast for non-gRPC
// traffic so the per-request cost is ~1 string compare.
func (g *GRPCInspect) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Reject the mTLS-bypass: HTTP/1.1 Upgrade: h2c
		if h2cUpgrade(r) {
			g.log(r, "HTTP2_UPGRADE_BLOCKED",
				"h2c Upgrade: rejected to prevent mTLS bypass")
			respondJSONError(w, http.StatusForbidden, "HTTP2_UPGRADE_BLOCKED",
				"HTTP/1.1 Upgrade to h2c is rejected (would bypass mTLS)")
			return
		}
		// 2. Reject h2c PRI * HTTP/2.0 method (CONNECT-tunneled)
		if strings.HasPrefix(r.Method, "PRI") {
			g.log(r, "H2C_PRI_BLOCKED", "h2c PRI: rejected")
			respondJSONError(w, http.StatusForbidden, "H2C_PRI_BLOCKED",
				"h2c cleartext PRI rejected (would bypass mTLS)")
			return
		}
		// 3. Reject raw CONNECT
		if r.Method == http.MethodConnect {
			g.log(r, "CONNECT_BLOCKED", "raw CONNECT rejected")
			respondJSONError(w, http.StatusForbidden, "CONNECT_BLOCKED",
				"CONNECT method not allowed on this proxy")
			return
		}
		// 4. If this looks like gRPC, validate path + size + body
		if looksGRPC(r) {
			if reason := g.validateGRPCRequest(r); reason != "" {
				g.log(r, "GRPC_BLOCKED", reason)
				respondJSONError(w, http.StatusBadRequest, "GRPC_BLOCKED", reason)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func h2cUpgrade(r *http.Request) bool {
	if strings.EqualFold(r.Header.Get("Connection"), "Upgrade") &&
		strings.EqualFold(r.Header.Get("Upgrade"), "h2c") {
		return true
	}
	// HTTP/2 pseudo-headers exposed by Go's http.Request
	if r.Header.Get(":method") != "" || r.Header.Get(":path") != "" {
		return true
	}
	return false
}

func looksGRPC(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, grpcContentType) {
		return true
	}
	if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/") {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
		if len(parts) == 2 {
			return true
		}
	}
	return false
}

func (g *GRPCInspect) validateGRPCRequest(r *http.Request) string {
	// Path length cap
	if len(r.URL.Path) > grpcMaxPathBytes {
		return fmt.Sprintf("grpc path too long: %d > %d", len(r.URL.Path), grpcMaxPathBytes)
	}
	// gRPC path shape: /package.Service/Method
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if len(parts) != 2 {
		return fmt.Sprintf("grpc path must be /<package>.<Service>/<Method>, got %q", r.URL.Path)
	}
	serviceMethod := parts[0] + "/" + parts[1]
	if !grpcMethodRE.MatchString(serviceMethod) {
		return fmt.Sprintf("grpc method %q does not match /<package>.<Service>/<Method> pattern", serviceMethod)
	}
	// gRPC content-type sub-format check (e.g. application/grpc+proto
	// or application/grpc;application/grpc-web+proto).  An empty
	// sub-type is also OK; non-empty must be alphanumeric+dot.
	ct := r.Header.Get("Content-Type")
	if i := strings.Index(ct, ";"); i > 0 {
		ct = ct[:i]
	}
	sub := strings.TrimPrefix(ct, grpcContentType)
	if sub != "" {
		if !strings.HasPrefix(sub, "+") || !grpcProtoRE.MatchString(strings.TrimPrefix(sub, "+")) {
			return fmt.Sprintf("invalid grpc content-type sub-format: %q", ct)
		}
	}
	// Content-Length cap
	if r.ContentLength > int64(g.maxBodyBytes) {
		return fmt.Sprintf("grpc frame too large: %d > %d", r.ContentLength, g.maxBodyBytes)
	}
	// Body sniff: first 5 bytes must look like a gRPC frame header
	//   1 byte  flags (printable, e.g. 0x00 no-compress)
	//   4 bytes length
	if r.Body != nil && r.ContentLength > 0 && r.ContentLength <= int64(g.maxBodyBytes) {
		sniff := make([]byte, 5)
		n, _ := io.ReadFull(io.LimitReader(r.Body, int64(len(sniff))), sniff)
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(sniff[:n]), r.Body))
		if n >= 5 {
			length := (uint32(sniff[1]) << 24) | (uint32(sniff[2]) << 16) |
				(uint32(sniff[3]) << 8) | uint32(sniff[4])
			if length > uint32(g.maxBodyBytes) {
				return fmt.Sprintf("grpc declared frame length %d exceeds %d",
					length, g.maxBodyBytes)
			}
		}
	}
	return ""
}

func (g *GRPCInspect) log(r *http.Request, code, msg string) {
	if g.audit != nil {
		var ip net.IP
		if s := clientIPString(r); s != "" {
			if parsed := net.ParseIP(s); parsed != nil {
				ip = parsed
			}
		}
		g.audit.Log(audit.Entry{
			Action:       "block",
			ResourceType: "grpc_inspect",
			Details:      map[string]string{"code": code, "msg": msg, "path": r.URL.Path, "method": r.Method},
			IPAddress:    ip,
		})
	}
}
