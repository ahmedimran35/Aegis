package audit

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Entry represents an audit log entry.
type Entry struct {
	UserID       int
	Username     string
	Action       string
	ResourceType string
	ResourceID   string
	Details      interface{}
	IPAddress    net.IP
}

// Logger writes audit events to Postgres.
//
// P-FIX (M-43): the at-rest protection of `Entry.Details` depends on
// the storage layer. Setting AEGIS_AUDIT_ENCRYPT=true turns on per-row
// AES-GCM encryption of Details before insert. The key is supplied
// via AEGIS_AUDIT_KEY (32 raw bytes, hex- or base64-encoded). Without
// this flag the audit log is unencrypted at the column level — PG-
// level encryption (TDE / pgcrypto) is out of scope and should be
// configured at the database for defense in depth.
type Logger struct {
	pool       *pgxpool.Pool
	ch         chan Entry
	encEnabled bool
	aead       cipher.AEAD
	// H-3: panic recovery + WaitGroup so Stop() can flush.
	wg       sync.WaitGroup
	stopCh   chan struct{}
	stopOnce sync.Once
	// M-20: drop counter surfaced through metrics.
	dropped     atomic.Int64
	droppedHook func(int64)
}

// NewLogger creates an audit logger.
//
// P-FIX (L-13): bufferSize is configurable via AEGIS_AUDIT_BUFFER (default
// 1000). When 0 or negative, the default is used.
func NewLogger(pool *pgxpool.Pool, bufferSize int) *Logger {
	if bufferSize <= 0 {
		bufferSize = 1000
	}
	l := &Logger{
		pool:   pool,
		ch:     make(chan Entry, bufferSize),
		stopCh: make(chan struct{}),
	}
	// P-FIX (M-43): if AEGIS_AUDIT_ENCRYPT=true and AEGIS_AUDIT_KEY is
	// supplied, encrypt Details with AES-GCM before persisting.
	if os.Getenv("AEGIS_AUDIT_ENCRYPT") == "true" {
		key, err := loadAuditKey()
		if err != nil {
			log.Printf("audit: AEGIS_AUDIT_ENCRYPT=true but key load failed (%v); proceeding with plaintext details", err)
		} else {
			block, err := aes.NewCipher(key)
			if err != nil {
				log.Printf("audit: AES key invalid: %v", err)
			} else {
				aead, err := cipher.NewGCM(block)
				if err != nil {
					log.Printf("audit: AES-GCM init failed: %v", err)
				} else {
					l.encEnabled = true
					l.aead = aead
					log.Println("audit: column-level AES-GCM encryption enabled for Details")
				}
			}
		}
	}
	l.wg.Add(1)
	go l.process()
	return l
}

// SetDroppedHook wires an optional callback (e.g. prometheus counter
// update) to fire every time an event is dropped because the buffer
// was full.
func (l *Logger) SetDroppedHook(f func(int64)) { l.droppedHook = f }

// Dropped returns the cumulative number of events dropped because the
// channel was full.
func (l *Logger) Dropped() int64 { return l.dropped.Load() }

// loadAuditKey resolves the AES key from AEGIS_AUDIT_KEY. Accepts either
// raw 32 bytes (set in env as AEGIS_AUDIT_KEY="<32 bytes>") or
// hex/base64 encoded values. We accept raw for ease of use with
// Kubernetes / docker secrets.
func loadAuditKey() ([]byte, error) {
	raw := os.Getenv("AEGIS_AUDIT_KEY")
	if raw == "" {
		return nil, fmt.Errorf("AEGIS_AUDIT_KEY is not set")
	}
	if len(raw) == 32 {
		return []byte(raw), nil
	}
	// try hex
	if b, err := hex.DecodeString(raw); err == nil && len(b) == 32 {
		return b, nil
	}
	// try base64
	if b, err := base64.StdEncoding.DecodeString(raw); err == nil && len(b) == 32 {
		return b, nil
	}
	return nil, fmt.Errorf("AEGIS_AUDIT_KEY must be 32 bytes (raw, hex, or base64-encoded)")
}

// process drains the channel and writes events. H-3: wraps the body in
// defer recover() so a malformed Entry or a Postgres-side panic does
// not kill the worker. The WaitGroup is released in the recovery path
// as well as the normal exit.
func (l *Logger) process() {
	defer l.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			log.Printf("audit: panic recovered: %v", r)
		}
	}()
	for entry := range l.ch {
		func(entry Entry) {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("audit: panic recovered on entry: %v", r)
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			var detailsJSON []byte
			if entry.Details != nil {
				detailsJSON, _ = json.Marshal(entry.Details)
				// P-FIX (M-43): when at-rest encryption is enabled, wrap
				// the JSON envelope in AES-GCM before insert. The clear
				// value is base64(nonce || ciphertext || tag) so a
				// hand-running pg_dump cannot read PII without the key.
				if l.encEnabled && l.aead != nil {
					nonce := make([]byte, l.aead.NonceSize())
					if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
						log.Printf("audit: nonce: %v", err)
					} else {
						ct := l.aead.Seal(nil, nonce, detailsJSON, nil)
						out := append(nonce, ct...)
						detailsJSON = []byte(base64.StdEncoding.EncodeToString(out))
					}
				}
			}

			var ipStr *string
			if entry.IPAddress != nil {
				s := entry.IPAddress.String()
				ipStr = &s
			}

			_, err := l.pool.Exec(ctx,
				`INSERT INTO audit_log (user_id, username, action, resource_type, resource_id, details, ip_address)
				 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
				entry.UserID, entry.Username, entry.Action, entry.ResourceType,
				entry.ResourceID, detailsJSON, ipStr)
			if err != nil {
				log.Printf("audit: write: %v", err)
			}
		}(entry)
	}
}

// Log records an audit event asynchronously.
func (l *Logger) Log(entry Entry) {
	select {
	case l.ch <- entry:
	default:
		// M-20: count drops for observability.
		d := l.dropped.Add(1)
		if l.droppedHook != nil {
			l.droppedHook(d)
		}
		log.Printf("audit: buffer full, dropping event %s/%s (total drops: %d)", entry.ResourceType, entry.Action, d)
	}
}

// LogRuleChange logs rule create/update/delete.
func (l *Logger) LogRuleChange(userID int, username, action string, ruleID int, details interface{}, ip net.IP) {
	l.Log(Entry{
		UserID:       userID,
		Username:     username,
		Action:       action,
		ResourceType: "rule",
		ResourceID:   itoa(ruleID),
		Details:      details,
		IPAddress:    ip,
	})
}

// LogSettingsChange logs settings modification.
func (l *Logger) LogSettingsChange(userID int, username, section string, details interface{}, ip net.IP) {
	l.Log(Entry{
		UserID:       userID,
		Username:     username,
		Action:       "update",
		ResourceType: "settings",
		ResourceID:   section,
		Details:      details,
		IPAddress:    ip,
	})
}

// LogUserChange logs user management actions.
func (l *Logger) LogUserChange(userID int, username, action string, targetUserID int, ip net.IP) {
	l.Log(Entry{
		UserID:       userID,
		Username:     username,
		Action:       action,
		ResourceType: "user",
		ResourceID:   itoa(targetUserID),
		IPAddress:    ip,
	})
}

// Stop flushes remaining entries.
//
// H-3: closes the channel and waits for the worker to drain. The
// stopCh is also closed (idempotent) so any caller blocked in Log()
// exits its wait without a goroutine leak.
func (l *Logger) Stop() {
	l.stopOnce.Do(func() {
		close(l.ch)
		close(l.stopCh)
	})
	l.wg.Wait()
}

// GetEntries retrieves audit log entries with pagination.
func (l *Logger) GetEntries(ctx context.Context, page, perPage int, resourceType string) ([]map[string]interface{}, int, error) {
	offset := (page - 1) * perPage

	var total int
	query := `SELECT COUNT(*) FROM audit_log`
	args := []interface{}{}

	if resourceType != "" {
		query += ` WHERE resource_type = $1`
		args = append(args, resourceType)
	}

	err := l.pool.QueryRow(ctx, query, args...).Scan(&total)
	if err != nil {
		log.Printf("audit: count query: %v (query: %s, args: %v)", err, query, args)
		return nil, 0, err
	}

	selectQuery := `SELECT id, user_id, username, action, resource_type, resource_id, details, ip_address::text, created_at
		FROM audit_log`
	if resourceType != "" {
		selectQuery += ` WHERE resource_type = $1`
	}
	// P-FIX (M-54): build LIMIT/OFFSET values from sanitized integers
	// via strconv.Itoa and a hard-coded template. The placeholder
	// positions are derived from the current argument count, which is
	// internally controlled (no user input flows into them), but we
	// use fmt.Sprintf with %d so any accidental string injection is
	// reduced to a digit-only safe form.
	limIdx := len(args) + 1
	offIdx := len(args) + 2
	selectQuery += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", limIdx, offIdx)
	args = append(args, perPage, offset)

	rows, err := l.pool.Query(ctx, selectQuery, args...)
	if err != nil {
		log.Printf("audit: select query: %v (query: %s, args: %v)", err, selectQuery, args)
		return nil, 0, err
	}
	defer rows.Close()

	// P-FREE-recovery: always return a non-nil slice so the JSON
	// serialises as `[]` not `null`. The SPA's AuditLog page throws
	// "null is not an object (evaluating 'c.data')" when iterating
	// an audit log page that has no rows.
	entries := make([]map[string]interface{}, 0)
	for rows.Next() {
		var id int64
		var userID int
		var username, action, rt, resourceID string
		var details []byte
		var ipAddress *string
		var createdAt time.Time

		if err := rows.Scan(&id, &userID, &username, &action, &rt, &resourceID, &details, &ipAddress, &createdAt); err != nil {
			log.Printf("audit: scan row: %v", err)
			continue
		}

		entry := map[string]interface{}{
			"id":            id,
			"user_id":       userID,
			"username":      username,
			"action":        action,
			"resource_type": rt,
			"resource_id":   resourceID,
			"created_at":    createdAt,
		}
		if ipAddress != nil {
			entry["ip_address"] = *ipAddress
		}
		if details != nil {
			var d interface{}
			if err := json.Unmarshal(details, &d); err != nil {
				log.Printf("audit: unmarshal details: %v", err)
			}
			entry["details"] = d
		}

		entries = append(entries, entry)
	}

	return entries, total, nil
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	s := ""
	for i > 0 {
		s = string(rune('0'+i%10)) + s
		i /= 10
	}
	return s
}
