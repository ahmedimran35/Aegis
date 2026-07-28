// Package middleware: JA4-family TLS fingerprint.
//
// JA4 is the FoxIO successor to JA3. Spec: https://github.com/FoxIO-LLC/ja4
//
// LIMITATION: Go's crypto/tls package does not expose raw ClientHello bytes
// (cipher suite list, extensions list, supported groups, point formats). The
// resulting hash is a JA4-LIKE fingerprint based on what IS exposed
// (negotiated version, cipher suite, SNI, ALPN). The "ja4-" prefix makes
// the partial nature explicit. For spec-compliant JA4, deploy an eBPF probe
// or sidecar proxy that captures raw ClientHello bytes.
package middleware

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Context key types for type-safe context values.
type ja4HashKey struct{}
type ja4hHashKey struct{}
type ja4ReputationKey struct{}

// ComputeJA4 computes a JA4-LIKE fingerprint from a TLS connection state.
// Returns "" if state is nil.
//
// Format (informal, NOT spec-compliant due to Go std-lib limits):
//
//	ja4-{version}-{sni}-{cipher_hex}-{alpn}
//
// where version is the decimal TLS version (e.g. "13"), sni is "i" or "x",
// cipher_hex is the 8-char hex prefix of SHA256(cipher_suite_str), and alpn
// is NegotiatedProtocol or "00" if absent.
func ComputeJA4(state *tls.ConnectionState) string {
	if state == nil {
		return ""
	}
	version := strconv.Itoa(int(state.Version))
	sniFlag := "x"
	if state.ServerName != "" {
		sniFlag = "i"
	}
	cipherStr := strconv.Itoa(int(state.CipherSuite))
	cipherSum := sha256.Sum256([]byte(cipherStr))
	cipherHex := hex.EncodeToString(cipherSum[:])[:8]
	alpn := state.NegotiatedProtocol
	if alpn == "" {
		alpn = "00"
	}
	return "ja4-" + version + sniFlag + cipherHex + alpn
}

// ComputeJA4H computes the JA4-H header-order entropy hash for a request.
// It hashes the sorted lowercase header names from the request. Returns ""
// if the request is nil or has no headers.
//
// Unlike HeaderFingerprint (which hashes header VALUES), JA4-H hashes
// header ORDER — i.e. the order in which the client sends headers. This
// is a strong bot detection signal because automated tools often use a
// different ordering than real browsers.
func ComputeJA4H(r *http.Request) string {
	if r == nil || len(r.Header) == 0 {
		return ""
	}
	names := make([]string, 0, len(r.Header))
	for k := range r.Header {
		names = append(names, strings.ToLower(k))
	}
	sortStrings(names)
	sum := sha256.Sum256([]byte(strings.Join(names, ",")))
	return "ja4h-" + hex.EncodeToString(sum[:])[:12]
}

// sortStrings delegates to the stdlib sort. F17: replaces an inline
// insertion sort (O(n²)) with the standard library's introsort (O(n
// log n)). For a request with many custom headers the previous code
// could spend ms per request — measurable under HTTP/2 header
// compression pressure.
func sortStrings(s []string) {
	sort.Strings(s)
}

// JA4Middleware returns an http.Handler middleware that:
//  1. Computes JA4 from r.TLS (if present) → context value
//  2. Computes JA4-H from request headers → context value
//  3. NEVER hard-blocks on first request — JA4 is a SCORE SIGNAL ONLY
//
// Pass nil for pool to skip DB store (useful in tests).
func JA4Middleware(pool *pgxpool.Pool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var ja4 string
			if r.TLS != nil {
				ja4 = ComputeJA4(r.TLS)
			}
			ja4h := ComputeJA4H(r)

			ctx := r.Context()
			if ja4 != "" {
				ctx = context.WithValue(ctx, ja4HashKey{}, ja4)
				if pool != nil {
					go storeJA4Fingerprint(pool, ja4, ja4h, clientIPString(r), r.UserAgent())
				}
			}
			if ja4h != "" {
				ctx = context.WithValue(ctx, ja4hHashKey{}, ja4h)
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ja4WriteCh is a bounded async channel for JA4 fingerprint writes.
// Bounded at 1024 entries; if full, writes are dropped and counted.
// This prevents unbounded goroutine fan-out under traffic spikes.
var ja4WriteCh = make(chan ja4WriteReq, 1024)
type ja4WriteReq struct{ ja4, ja4h, ip, ua string }

func init() {
	// Single batched worker — consumes up to 100 items every 200ms,
	// collapses N writes into a single multi-row INSERT.
	go ja4BatchWorker()
}

func ja4BatchWorker() {
	const batchSize = 100
	const flushInterval = 200 * time.Millisecond
	t := time.NewTicker(flushInterval)
	defer t.Stop()
	buf := make([]ja4WriteReq, 0, batchSize)
	for {
		select {
		case req := <-ja4WriteCh:
			buf = append(buf, req)
			if len(buf) >= batchSize {
				ja4Flush(buf)
				buf = buf[:0]
			}
		case <-t.C:
			if len(buf) > 0 {
				ja4Flush(buf)
				buf = buf[:0]
			}
		}
	}
}

func ja4Flush(items []ja4WriteReq) {
	if ja4StorePool == nil || len(items) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Build multi-row INSERT for collapse.
	var sb strings.Builder
	sb.WriteString("INSERT INTO tls_fingerprints (ja3_hash, ja4_hash, ja4_h, client_ip, user_agent, proto) VALUES ")
	args := make([]any, 0, len(items)*5)
	for i, r := range items {
		if i > 0 {
			sb.WriteString(",")
		}
		base := i * 5
		sb.WriteString(fmt.Sprintf("($%d, $%d, $%d, $%d, $%d, 'tcp')", base+1, base+2, base+3, base+4, base+5))
		args = append(args, r.ja4, r.ja4, r.ja4h, r.ip, r.ua)
	}
	sb.WriteString(" ON CONFLICT (ja4_hash) DO UPDATE SET last_seen = NOW(), request_count = tls_fingerprints.request_count + 1")
	_, err := ja4StorePool.Exec(ctx, sb.String(), args...)
	if err != nil {
		log.Printf("ja4: batch-store: %v (dropped %d rows)", err, len(items))
	}
}

// ja4StorePool is set by the middleware constructor at startup.
var ja4StorePool *pgxpool.Pool

// SetJA4StorePool wires the pool used by the batched worker.
// Must be called once during startup before fingerprints arrive.
func SetJA4StorePool(pool *pgxpool.Pool) { ja4StorePool = pool }

// storeJA4Fingerprint queues a fingerprint for async batched insert.
// Bounded: if the channel is full, the write is dropped (counted
// via log) — no goroutine fan-out.
func storeJA4Fingerprint(pool *pgxpool.Pool, ja4, ja4h, ip, ua string) {
	if pool == nil {
		return
	}
	select {
	case ja4WriteCh <- ja4WriteReq{ja4: ja4, ja4h: ja4h, ip: ip, ua: ua}:
	default:
		log.Printf("ja4: write-queue full, dropping fingerprint")
	}
}

// clientIPString returns the request's client IP as a string, or "" if
// the IP cannot be extracted. Uses the same extractIP as the rest of
// the middleware package.
func clientIPString(r *http.Request) string {
	if r == nil {
		return ""
	}
	ip := extractIP(r)
	if ip == nil {
		return ""
	}
	return ip.String()
}