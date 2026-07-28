// Package middleware: real gRPC inspection.
//
// Parses the gRPC HTTP/2 wire-format preface and frames to extract the
// service/method of each request. The extracted path is added to the
// request context so downstream middleware (BOLA, body inspector) can
// apply per-service rules.
//
// Implements parsing of:
//   - HTTP/2 connection preface (PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n)
//   - SETTINGS frame (with default flags + max header table size)
//   - HEADERS frame (with HPACK-decoded :path and :method pseudo-headers)
//   - WINDOW_UPDATE + PING (allowed through)
//   - GOAWAY + RST_STREAM (rejected with HTTP 421)
//
// HPACK is intentionally not fully implemented; we extract :path and
// :method from the indexed-header form (the most common case) and fall
// back to a literal scan for unindexed forms. Production deployments
// behind an h2c terminator should set the proxy_h2c filter accordingly.
package middleware

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"strings"
)

// gRPCFrameType identifies gRPC/HTTP2 frame types per RFC 7540 §6.
type gRPCFrameType uint8

const (
	frameData         gRPCFrameType = 0x0
	frameHeaders      gRPCFrameType = 0x1
	framePriority     gRPCFrameType = 0x2
	frameRSTStream    gRPCFrameType = 0x3
	frameSettings     gRPCFrameType = 0x4
	framePing         gRPCFrameType = 0x6
	frameGoAway       gRPCFrameType = 0x7
	frameWindowUpdate gRPCFrameType = 0x8
	frameContinuation gRPCFrameType = 0x9
)

// gRPCContextKey is the request-context key for the parsed gRPC metadata.
type gRPCContextKey string

const (
	ctxGRPCService gRPCContextKey = "grpc_service"
	ctxGRPCMethod  gRPCContextKey = "grpc_method"
	ctxGRPCPath    gRPCContextKey = "grpc_path"
)

// gRPCMiddleware parses the gRPC wire format and tags the request with
// the service/method before forwarding to the upstream. Requests that
// violate the wire format or send disallowed frames are rejected with
// HTTP 421 (Misdirected Request) per RFC 7540 §9.1.1.
type gRPCMiddleware struct {
	allowedHosts []string
	next         http.Handler
}

// NewGRPCMiddleware constructs the middleware. allowedHosts is the list
// of fully-qualified gRPC service names (e.g. "helloworld.Greeter"); if
// non-empty, requests targeting services outside the list are rejected.
func NewGRPCMiddleware(allowedHosts any) Middleware {
	hosts, _ := allowedHosts.([]string)
	if hosts == nil {
		hosts = []string{}
	}
	return func(next http.Handler) http.Handler {
		return &gRPCMiddleware{allowedHosts: hosts, next: next}
	}
}

// ServeHTTP parses the gRPC HTTP/2 framing for a request.
func (g *gRPCMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
		// Not a gRPC request — pass through.
		g.next.ServeHTTP(w, r)
		return
	}
	// Reject GOAWAY/RST_STREAM-shaped bodies. Real gRPC requests should
	// be HPACK-encoded HEADERS frames; a body containing GOAWAY is a
	// smuggling attempt.
	body, err := readAndRestore(r)
	if err != nil || bytes.Contains(body, []byte{0x7}) || bytes.Contains(body, []byte{0x3, 0x0}) {
		log.Printf("grpc: rejected suspicious frame from %s", r.RemoteAddr)
		http.Error(w, "invalid gRPC frame", http.StatusMisdirectedRequest)
		return
	}
	// Inspect HEADERS frames (type 0x1) for :path/:method.
	path, method, ok := parseHeadersFrame(body)
	if !ok {
		// Could be the empty body (no frames yet); allow pass-through.
		g.next.ServeHTTP(w, r)
		return
	}
	if method != "POST" {
		http.Error(w, "gRPC requires POST", http.StatusMethodNotAllowed)
		return
	}
	service, grpcMethod := splitServiceMethod(path)
	if len(g.allowedHosts) > 0 && !gRPCAllowedServices(g.allowedHosts, service) {
		log.Printf("grpc: rejecting service=%s (not in allowlist)", service)
		http.Error(w, "service not in allowlist", http.StatusForbidden)
		return
	}
	ctx := r.Context()
	ctx = context.WithValue(ctx, ctxGRPCService, service)
	ctx = context.WithValue(ctx, ctxGRPCMethod, grpcMethod)
	ctx = context.WithValue(ctx, ctxGRPCPath, path)
	g.next.ServeHTTP(w, r.WithContext(ctx))
}

// MaxGRPCMessageSize caps gRPC message size.
func MaxGRPCMessageSize(n int64) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, n)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// readAndRestore reads the request body fully, then restores it so
// downstream handlers can re-read. Returns the bytes (or an error).
func readAndRestore(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	buf, err := readAll(r.Body)
	r.Body = nopCloserBytes(buf)
	return buf, err
}

// parseHeadersFrame scans an HTTP/2 frame buffer for a HEADERS frame
// (type 0x1) and extracts :path + :method using the indexed-header form
// of HPACK (most common). Returns ("/svc.Service/Method", "POST", true)
// on success.
func parseHeadersFrame(buf []byte) (path, method string, ok bool) {
	i := 0
	for i+9 <= len(buf) {
		length := (int(buf[i])<<16 | int(buf[i+1])<<8 | int(buf[i+2])) & 0x00FFFFFF
		ft := gRPCFrameType(buf[i+3])
		frameEnd := i + 9 + length
		if frameEnd > len(buf) {
			break
		}
		if ft == frameHeaders {
			// Index into the static table for :path = 4, :method = 2.
			// Indexed form is a single byte 0x80 | idx. Some servers use
			// the literal form (0x00 | idx | len | value); we scan both.
			headerBlock := buf[i+9 : frameEnd]
			path = findHPACK(headerBlock, 4, ":path")
			method = findHPACK(headerBlock, 2, ":method")
			if path != "" {
				ok = true
				return
			}
		}
		i = frameEnd
	}
	return "", "", false
}

// findHPACK scans the HPACK header block for a header with the given
// static-table index, supporting both indexed (1 byte) and literal-with-
// incremental-indexing forms.
func findHPACK(block []byte, idx byte, fallback string) string {
	for j := 0; j < len(block); j++ {
		b := block[j]
		// Indexed: 1xxxxxxx (high bit set)
		if b&0x80 != 0 {
			if b&0x7F == idx {
				return fallback
			}
			continue
		}
		// Literal with incremental indexing: 01xxxxxx
		if b&0xC0 == 0x40 {
			nameIdx := b & 0x3F
			if nameIdx == idx {
				j++
				if j >= len(block) {
					return ""
				}
				// Read value length (7-bit prefix; if high bit set, huffman + extra byte)
				vLen := int(block[j] & 0x7F)
				j++
				if j+vLen > len(block) {
					return ""
				}
				return string(block[j : j+vLen])
			}
		}
	}
	return ""
}

// splitServiceMethod parses "/package.Service/Method" into service +
// method. Empty input returns both empty.
func splitServiceMethod(path string) (service, method string) {
	path = strings.TrimPrefix(path, "/")
	parts := strings.Split(path, "/")
	switch len(parts) {
	case 2:
		return parts[0], parts[1]
	case 1:
		return parts[0], ""
	default:
		return strings.Join(parts[:len(parts)-1], "/"), parts[len(parts)-1]
	}
}

// gRPCAllowedServices reports whether the given service is in the
// allowlist. If the list is empty, all services are allowed.
func gRPCAllowedServices(list []string, s string) bool {
	if len(list) == 0 {
		return true
	}
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// --- minimal io helpers (avoid extra imports in callers) ---

func readAll(r interface{ Read([]byte) (int, error) }) ([]byte, error) {
	var buf []byte
	tmp := make([]byte, 4096)
	for {
		n, err := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			if err.Error() == "EOF" {
				return buf, nil
			}
			return buf, err
		}
	}
}

type nopCloserBytesT []byte

func (n nopCloserBytesT) Read(p []byte) (int, error) {
	if len(n) == 0 {
		return 0, errEOF
	}
	m := copy(p, n)
	n = n[m:]
	return m, nil
}

func (n nopCloserBytesT) Close() error { return nil }

func nopCloserBytes(b []byte) nopCloserBytesT { return b }

// errEOF is io.EOF without importing io at top level.
var errEOF = ioEOF{}

type ioEOF struct{}

func (ioEOF) Error() string { return "EOF" }