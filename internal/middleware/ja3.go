package middleware

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Context key types for type-safe context values.
type ja3HashKey struct{}
type ja3ReputationKey struct{}

// TLSFingerprint holds JA3 hash info for a client.
type TLSFingerprint struct {
	JA3Hash    string
	JA3Full    string
	ClientIP   string
	UserAgent  string
	Reputation string
}

// JA3Checker tracks and filters by TLS fingerprints.
// ja3WriteCh is a bounded async channel for JA3 fingerprint writes.
// Mirrors the JA4 batching pattern so the two stacks have identical
// performance characteristics.
var ja3WriteCh = make(chan ja3WriteReq, 1024)
type ja3WriteReq struct{ ja3, ip, ua string }

func init() { go ja3BatchWorker() }

func ja3BatchWorker() {
	const batchSize = 100
	const flushInterval = 200 * time.Millisecond
	t := time.NewTicker(flushInterval)
	defer t.Stop()
	buf := make([]ja3WriteReq, 0, batchSize)
	for {
		select {
		case req := <-ja3WriteCh:
			buf = append(buf, req)
			if len(buf) >= batchSize {
				ja3Flush(buf)
				buf = buf[:0]
			}
		case <-t.C:
			if len(buf) > 0 {
				ja3Flush(buf)
				buf = buf[:0]
			}
		}
	}
}

func ja3Flush(items []ja3WriteReq) {
	if ja3StorePool == nil || len(items) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var sb strings.Builder
	sb.WriteString("INSERT INTO tls_fingerprints (ja3_hash, client_ip, user_agent, proto) VALUES ")
	args := make([]any, 0, len(items)*3)
	for i, r := range items {
		if i > 0 { sb.WriteString(",") }
		base := i * 3
		sb.WriteString(fmt.Sprintf("($%d, $%d, $%d, 'tcp')", base+1, base+2, base+3))
		args = append(args, r.ja3, r.ip, r.ua)
	}
	sb.WriteString(" ON CONFLICT (ja3_hash) DO UPDATE SET last_seen = NOW(), request_count = tls_fingerprints.request_count + 1")
	_, err := ja3StorePool.Exec(ctx, sb.String(), args...)
	if err != nil {
		log.Printf("ja3: batch-store: %v (dropped %d rows)", err, len(items))
	}
}

// ja3StorePool is set by the middleware constructor at startup.
var ja3StorePool *pgxpool.Pool

// SetJA3StorePool wires the pool used by the batched worker.
func SetJA3StorePool(pool *pgxpool.Pool) { ja3StorePool = pool }

// JA3Checker tracks and filters by TLS fingerprints.
type JA3Checker struct {
	pool   *pgxpool.Pool
	mu     sync.RWMutex
	cache  map[string]string // ip -> ja3_hash
	stopCh chan struct{}
}

// NewJA3Checker creates a TLS fingerprint checker.
func NewJA3Checker(pool *pgxpool.Pool) *JA3Checker {
	return &JA3Checker{
		pool:   pool,
		cache:  make(map[string]string),
		stopCh: make(chan struct{}),
	}
}

// ComputeJA3 computes a "JA3-like" fingerprint from TLS connection state.
//
// IMPORTANT: Go's crypto/tls package does not expose the raw ClientHello
// bytes (extensions list, supported curves, point formats) that real JA3
// requires. This implementation extracts what IS exposed (TLS version,
// negotiated cipher suite, SNI server name) and produces a stable hash
// suitable for client reputation tracking. The resulting hash should be
// treated as a JA3-LIKE fingerprint, NOT a spec-compliant JA3.
//
// For bot detection based on actual TLS ClientHello characteristics,
// use a packet-level sniffer or an external proxy that captures raw bytes.
//
// F34: the previous comma-joined format allowed a collision between
// (Version=12, Cipher=34, SNI="X") and (Version=1, Cipher=23, SNI="4,X")
// etc. We use a NUL separator (which cannot appear in any of these
// fields) plus per-field length prefixing.
func ComputeJA3(state *tls.ConnectionState) string {
	if state == nil {
		return ""
	}

	parts := []string{
		strconv.Itoa(int(state.Version)),
		strconv.Itoa(int(state.CipherSuite)),
		state.ServerName, // proxy for SNI extension presence
	}

	// Go's TLS state does not expose supported curves or point formats.
	// Leave empty (matches JA3 spec format).

	// F34: use NUL as a delimiter and length-prefix each field so a
	// ServerName containing a comma cannot collide with a different
	// field-split interpretation.
	var b strings.Builder
	for i, p := range parts {
		if i > 0 {
			b.WriteByte(0x1f) // ASCII Unit Separator
		}
		b.WriteString(strconv.Itoa(len(p)))
		b.WriteByte(':')
		b.WriteString(p)
	}
	hash := sha256.Sum256([]byte(b.String()))
	return "ja3like-" + hex.EncodeToString(hash[:16])
}

// HeaderFingerprint computes a stable fingerprint of HTTP request headers
// commonly used to identify bots: User-Agent, Accept, Accept-Encoding,
// Accept-Language. This is a useful bot-detection signal independent of
// TLS — applicable to cleartext HTTP, CDNs that terminate TLS, and
// self-hosted Aegis deployments behind a reverse proxy.
//
// Returns a sha256-prefixed hex hash. The "hf-" prefix makes it clear
// this is NOT JA3 and avoids collision with the TLS fingerprint space.
//
// F34: use length-prefixed ASCII Unit-Separator framing so a
// User-Agent like "Mozilla|5.0" cannot collide with the next field's
// value.
func HeaderFingerprint(r *http.Request) string {
	if r == nil {
		return ""
	}
	parts := []string{
		r.Header.Get("User-Agent"),
		r.Header.Get("Accept"),
		r.Header.Get("Accept-Encoding"),
		r.Header.Get("Accept-Language"),
		r.Header.Get("Sec-Ch-Ua"),
		r.Header.Get("Sec-Ch-Ua-Platform"),
	}
	var b strings.Builder
	for i, p := range parts {
		if i > 0 {
			b.WriteByte(0x1f) // ASCII Unit Separator
		}
		b.WriteString(strconv.Itoa(len(p)))
		b.WriteByte(':')
		b.WriteString(p)
	}
	hash := sha256.Sum256([]byte(b.String()))
	return "hf-" + hex.EncodeToString(hash[:16])
}

// ExtractJA3FromConn extracts JA3 from net.Conn if it's a tls.Conn.
func ExtractJA3FromConn(conn net.Conn) string {
	if tc, ok := conn.(*tls.Conn); ok {
		state := tc.ConnectionState()
		return ComputeJA3(&state)
	}
	return ""
}

// StoreFingerprint saves a TLS fingerprint to the database.
func (jc *JA3Checker) StoreFingerprint(ja3Hash, clientIP, userAgent string) {
	// Bounded: enqueue to async batched worker channel.
	select {
	case ja3WriteCh <- ja3WriteReq{ja3: ja3Hash, ip: clientIP, ua: userAgent}:
	default:
		log.Printf("ja3: write-queue full, dropping fingerprint")
	}
}

// GetReputation returns the reputation for a JA3 hash.
func (jc *JA3Checker) GetReputation(ja3Hash string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var reputation string
	err := jc.pool.QueryRow(ctx,
		`SELECT reputation FROM tls_fingerprints WHERE ja3_hash = $1`, ja3Hash).Scan(&reputation)
	if err != nil {
		return "unknown"
	}
	return reputation
}

// SetReputation updates the reputation for a JA3 hash.
func (jc *JA3Checker) SetReputation(ja3Hash, reputation string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := jc.pool.Exec(ctx,
		`UPDATE tls_fingerprints SET reputation = $1 WHERE ja3_hash = $2`,
		reputation, ja3Hash)
	return err
}

// Stop halts background goroutines.
func (jc *JA3Checker) Stop() {
	close(jc.stopCh)
}

// Middleware returns JA3 fingerprinting middleware. Falls back to
// HTTP-header fingerprint when TLS is not present (cleartext, behind CDN).
func (jc *JA3Checker) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r)
		ipStr := ""
		if ip != nil {
			ipStr = ip.String()
		}

		var fingerprint string
		if r.TLS != nil {
			fingerprint = ComputeJA3(r.TLS)
		} else {
			fingerprint = HeaderFingerprint(r)
		}

		if fingerprint != "" {
			go jc.StoreFingerprint(fingerprint, ipStr, r.UserAgent())

			reputation := jc.GetReputation(fingerprint)
			if reputation == "blocked" {
				log.Printf("ja3: blocked %s (hash: %s, reputation: %s)", ipStr, fingerprint[:min(8, len(fingerprint))], reputation)
				writeBlockError(w, "FINGERPRINT_BLOCKED", "your client fingerprint is blocked")
				return
			}

			ctx := context.WithValue(r.Context(), ja3HashKey{}, fingerprint)
			ctx = context.WithValue(ctx, ja3ReputationKey{}, reputation)
			r = r.WithContext(ctx)
		}

		next.ServeHTTP(w, r)
	})
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
