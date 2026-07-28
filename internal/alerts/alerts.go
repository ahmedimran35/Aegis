package alerts

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// Severity levels
const (
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

var severityOrder = map[string]int{
	SeverityLow:      1,
	SeverityMedium:   2,
	SeverityHigh:     3,
	SeverityCritical: 4,
}

// Event represents an alertable event.
type Event struct {
	Type      string `json:"type"`      // rule_block, ai_block, bot_block, anomaly
	Severity  string `json:"severity"`
	IP        string `json:"ip"`
	Path      string `json:"path"`
	Rule      string `json:"rule,omitempty"`
	Details   string `json:"details,omitempty"`
	Timestamp string `json:"timestamp"`
}

// Alerter sends alerts to configured webhook endpoints.
type Alerter struct {
	webhookURL  string
	minSeverity string
	// signingKey is the server-side master key used to compute the
	// X-Aegis-Signature header on outbound webhooks (P-FIX H-22). It must
	// be at least 32 bytes; shorter values are hashed to 32 bytes on
	// construction. The receiver verifies the header against the same key
	// (kept out of band via the deploy documentation).
	signingKey []byte
	client     *http.Client
	rdb        *redis.Client
	ch         chan Event
	stopCh     chan struct{}
	stopOnce   sync.Once
	mu         sync.RWMutex
}

// NewAlerter creates an alerter with async delivery.
//
// signingKey must be at least 32 bytes; if shorter, it is hashed with
// SHA-256 to derive a 32-byte key. Use the same constant across all
// cluster nodes (AEGIS_WEBHOOK_MASTER_KEY) so receivers can verify
// signatures from any node.
func NewAlerter(webhookURL, minSeverity string, rdb *redis.Client, signingKey []byte) *Alerter {
	if len(signingKey) < 32 {
		sum := sha256.Sum256(signingKey)
		signingKey = sum[:]
	}
	a := &Alerter{
		webhookURL:  webhookURL,
		minSeverity: minSeverity,
		signingKey:  signingKey,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		rdb:    rdb,
		ch:     make(chan Event, 1000),
		stopCh: make(chan struct{}),
	}

	if webhookURL != "" {
		go a.deliveryLoop()
	}

	return a
}

// Send queues an alert for delivery (non-blocking).
func (a *Alerter) Send(event Event) {
	a.mu.RLock()
	webhookURL := a.webhookURL
	minSev := a.minSeverity
	a.mu.RUnlock()

	if webhookURL == "" {
		return
	}

	// Check severity threshold
	if !meetsSeverity(event.Severity, minSev) {
		return
	}

	// Dedup: max 1 alert per (type, ip) per 5 minutes
	ctx := context.Background()
	dedupKey := fmt.Sprintf("alert:dedup:%s:%s", event.Type, event.IP)
	ok, err := a.rdb.SetNX(ctx, dedupKey, "1", 5*time.Minute).Result()
	if err != nil || !ok {
		return
	}

	event.Timestamp = time.Now().UTC().Format(time.RFC3339)

	select {
	case a.ch <- event:
	default:
		// Channel full, drop alert
		log.Printf("alerts: channel full, dropping alert for %s", event.Type)
	}
}

func (a *Alerter) deliveryLoop() {
	for {
		select {
		case event := <-a.ch:
			a.deliver(event)
		case <-a.stopCh:
			return
		}
	}
}

func (a *Alerter) deliver(event Event) {
	body, err := json.Marshal(event)
	if err != nil {
		log.Printf("alerts: marshal error: %v", err)
		return
	}

	a.mu.RLock()
	url := a.webhookURL
	key := a.signingKey
	a.mu.RUnlock()

	// P-FIX (H-22/M-42): every outbound webhook carries an HMAC-SHA256
	// signature and a unix timestamp. Receivers MUST verify both:
	//   X-Aegis-Timestamp: <unix-seconds>
	//   X-Aegis-Signature: sha256=<hex(hmac_sha256(key, "<ts>." + body))>
	// The signed payload includes the timestamp so a captured request
	// cannot be replayed past the receiver's freshness window (default
	// 5 minutes).
	timestamp := time.Now().Unix()
	signature := signWebhookBody(key, timestamp, body)

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		log.Printf("alerts: new request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Aegis-Timestamp", strconv.FormatInt(timestamp, 10))
	req.Header.Set("X-Aegis-Signature", signature)
	resp, err := a.client.Do(req)
	if err != nil {
		log.Printf("alerts: webhook error: %v", err)
		return
	}
	resp.Body.Close()

	if resp.StatusCode >= 400 {
		log.Printf("alerts: webhook returned %d", resp.StatusCode)
	}
}

// signWebhookBody computes the value of the X-Aegis-Signature header for a
// given (timestamp, body) tuple. It is exposed for receivers that want to
// verify Aegis-side signatures (e.g. internal test fixtures). Production
// receivers should re-implement this against their known shared key.
func signWebhookBody(key []byte, timestamp int64, body []byte) string {
	if len(key) == 0 {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	fmt.Fprintf(mac, "%d.", timestamp)
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// Stop halts the delivery loop.
func (a *Alerter) Stop() {
	a.stopOnce.Do(func() { close(a.stopCh) })
}

func meetsSeverity(eventSev, minSev string) bool {
	return severityOrder[eventSev] >= severityOrder[minSev]
}

// UpdateConfig changes the webhook URL and severity threshold.
func (a *Alerter) UpdateConfig(webhookURL, minSeverity string) {
	a.mu.Lock()
	a.webhookURL = webhookURL
	a.minSeverity = minSeverity
	a.mu.Unlock()
}

// VerifySignature validates an incoming X-Aegis-Signature header against
// the supplied (timestamp, body) tuple using key. Returns true only if
// the signature is well-formed, matches HMAC-SHA256(key, "<ts>." + body),
// AND timestamp is within ±maxSkew of now. Receivers should call this
// before trusting any inbound webhook claimed to be from Aegis.
//
// P-FIX (M-42): prevents trivial replay of captured requests; the
// timestamp is part of the signed material so an attacker cannot reuse
// a request with a fresh timestamp without the key.
func VerifySignature(key []byte, timestamp int64, body []byte, signature string, maxSkew time.Duration) bool {
	if len(key) == 0 || signature == "" {
		return false
	}
	// Freshness check first; this is a coarse filter.
	now := time.Now().Unix()
	if maxSkew <= 0 {
		maxSkew = 5 * time.Minute
	}
	diff := now - timestamp
	if diff < 0 {
		diff = -diff
	}
	if time.Duration(diff)*time.Second > maxSkew {
		return false
	}
	expected := signWebhookBody(key, timestamp, body)
	if len(expected) != len(signature) {
		return false
	}
	// Constant-time compare via hmac.Equal (which is in stdlib and is
	// constant-time on the two slices).
	return hmac.Equal([]byte(expected), []byte(signature))
}
