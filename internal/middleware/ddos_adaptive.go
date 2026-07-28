package middleware

import (
	"container/list"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// AdaptiveDDoS adds heuristic triggers on top of the connection-level
// DDoS protector. Detected scenarios:
//   1. URI entropy flood — many distinct random-looking URIs in a short
//      window (bot directory enumeration).
//   2. UA-entropy flood — random/distinct User-Agent values without
//      legitimate browser fingerprints.
//   3. Header anomaly — missing common headers (Accept, Accept-Language)
//      present on real browsers.
//   4. JA3/JA4 rarity — only one or two distinct fingerprints across many
//      IP sources (botnet).
type AdaptiveDDoS struct {
	db          *pgxpool.Pool
	mu          sync.RWMutex
	// H-7: seen is bounded by maxSeen (LRU). When a new IP arrives and
	// we are at the cap, the oldest entry is evicted.
	seen        map[string]*list.Element // ip → *entropyState (in ll)
	seenLL      *list.List
	maxSeen     int
	cleanupOnce sync.Once
	stopCh      chan struct{}
	cleanupDone chan struct{}
}

// H-7: default cap on adaptive DDoS tracked IPs.
const defaultAdaptiveMaxSeen = 50000

// entropyListEntry is the LRU-list value.
type entropyListEntry struct {
	ip  string
	st  *entropyState
}

type entropyState struct {
	uris     []string
	uas      []string
	ja3s     []string
	updated  time.Time
	lastFlag time.Time
}

// Config holds adaptive DDoS thresholds.
type AdaptiveConfig struct {
	URIEntropyThreshold   int           // distinct URIs before flag
	UAEntropyThreshold    int           // distinct UAs before flag
	HeaderAnomalyRequired int           // missing headers count to flag
	WindowDuration        time.Duration // sliding window
	BlockOnFlagFor        time.Duration // soft-block duration after flag
}

// DefaultAdaptiveConfig returns production-friendly defaults.
func DefaultAdaptiveConfig() AdaptiveConfig {
	return AdaptiveConfig{
		URIEntropyThreshold:   32,
		UAEntropyThreshold:    12,
		HeaderAnomalyRequired: 3,
		WindowDuration:        60 * time.Second,
		BlockOnFlagFor:        10 * time.Minute,
	}
}

// NewAdaptiveDDoS returns a stateless adaptive layer. db is currently unused
// but reserved for persisting flagged IPs so other nodes see the same block.
func NewAdaptiveDDoS(db *pgxpool.Pool) *AdaptiveDDoS {
	a := &AdaptiveDDoS{
		db:         db,
		seen:       make(map[string]*list.Element),
		seenLL:     list.New(),
		maxSeen:    defaultAdaptiveMaxSeen,
		stopCh:     make(chan struct{}),
		cleanupDone: make(chan struct{}),
	}
	go a.periodicCleanup()
	return a
}

// Stop halts the background cleanup goroutine.
func (a *AdaptiveDDoS) Stop() {
	select {
	case <-a.stopCh:
		return
	default:
		close(a.stopCh)
	}
	<-a.cleanupDone
}

// periodicCleanup evicts stale entries every 5 minutes and on Stop.
func (a *AdaptiveDDoS) periodicCleanup() {
	defer close(a.cleanupDone)
	defer func() {
		if r := recover(); r != nil {
			// never crash the process from a cleanup loop
			return
		}
	}()
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-a.stopCh:
			return
		case <-t.C:
			a.CleanupStale(10 * time.Minute)
		}
	}
}

// Evaluate inspects a request and returns (flagged, reasons). Stateless apart
// from the in-memory per-IP sliding window — sufficient for single-node
// Aegis; multi-node deployments should swap the in-memory map for Redis.
func (a *AdaptiveDDoS) Evaluate(ip, uri, ua, ja3 string, headers map[string][]string) (bool, []string) {
	if ip == "" {
		return false, nil
	}
	a.mu.Lock()
	el, ok := a.seen[ip]
	var st *entropyState
	if ok {
		st = el.Value.(*entropyListEntry).st
		a.seenLL.MoveToFront(el)
	} else {
		st = &entropyState{}
		el = a.seenLL.PushFront(&entropyListEntry{ip: ip, st: st})
		a.seen[ip] = el
		// H-7: evict oldest entries beyond the cap.
		for a.seenLL.Len() > a.maxSeen {
			oldest := a.seenLL.Back()
			if oldest == nil {
				break
			}
			a.seenLL.Remove(oldest)
			delete(a.seen, oldest.Value.(*entropyListEntry).ip)
		}
	}
	st.updated = time.Now()

	st.uris = append(st.uris, uri)
	if len(st.uris) > 512 {
		st.uris = st.uris[len(st.uris)-512:]
	}
	st.uas = append(st.uas, ua)
	if len(st.uas) > 128 {
		st.uas = st.uas[len(st.uas)-128:]
	}
	if ja3 != "" {
		st.ja3s = append(st.ja3s, ja3)
		if len(st.ja3s) > 256 {
			st.ja3s = st.ja3s[len(st.ja3s)-256:]
		}
	}

	reasons := []string{}
	uriDistinct := distinct(st.uris)
	if uriDistinct > 32 {
		reasons = append(reasons, "uri_entropy")
	}
	if distinct(st.uas) > 8 {
		reasons = append(reasons, "ua_entropy")
	}
	if !hasCommonHeaders(headers) {
		reasons = append(reasons, "header_anomaly")
	}
	if len(st.ja3s) > 100 && distinct(st.ja3s) <= 2 {
		reasons = append(reasons, "ja3_rarity")
	}
	flagged := false
	if len(reasons) >= 2 {
		flagged = true
		st.lastFlag = time.Now()
	}
	a.mu.Unlock()
	return flagged, reasons
}

func distinct(in []string) int {
	seen := make(map[string]struct{}, len(in))
	for _, v := range in {
		seen[v] = struct{}{}
	}
	return len(seen)
}

func hasCommonHeaders(h map[string][]string) bool {
	// Real browsers always send Accept and Accept-Language. Most bots miss
	// at least one.
	if len(h["Accept"]) == 0 {
		return false
	}
	if len(h["Accept-Language"]) == 0 {
		return false
	}
	return true
}

// CleanupStale removes ip entries not updated in a while. Called periodically.
//
// H-7: also enforces a hard cap (maxSeen). If the LRU is at the cap, the
// oldest entries are evicted regardless of age to keep memory bounded.
func (a *AdaptiveDDoS) CleanupStale(olderThan time.Duration) int {
	cutoff := time.Now().Add(-olderThan)
	a.mu.Lock()
	defer a.mu.Unlock()
	removed := 0
	for el := a.seenLL.Front(); el != nil; {
		next := el.Next()
		entry := el.Value.(*entropyListEntry)
		if entry.st.updated.Before(cutoff) {
			a.seenLL.Remove(el)
			delete(a.seen, entry.ip)
			removed++
		}
		el = next
	}
	// Enforce hard cap.
	for a.seenLL.Len() > a.maxSeen {
		oldest := a.seenLL.Back()
		if oldest == nil {
			break
		}
		a.seenLL.Remove(oldest)
		delete(a.seen, oldest.Value.(*entropyListEntry).ip)
		removed++
	}
	return removed
}

// ShannonEntropy returns bits-per-symbol of a string. Used for noise-detection.
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	counts := make(map[rune]int)
	for _, r := range s {
		counts[r]++
	}
	var h float64
	n := float64(len(s))
	for _, c := range counts {
		p := float64(c) / n
		if p > 0 {
			h -= p * math.Log2(p)
		}
	}
	return h
}

// IsURIRandom returns true when the path looks random enough to indicate an
// enumeration bot. We treat entropy > 4.5 AND path contains a 24+ hex/digit
// run as random — catches uuid-style IDs and base64-encoded blobs.
func IsURIRandom(path string) bool {
	if strings.Contains(path, "..") {
		return true
	}
	path = strings.TrimPrefix(path, "/")
	if len(path) < 12 {
		return false
	}
	if ShannonEntropy(path) > 4.5 {
		return true
	}
	runLen, maxRun := 0, 0
	for _, c := range path {
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			runLen++
			if runLen > maxRun {
				maxRun = runLen
			}
		} else {
			runLen = 0
		}
	}
	return maxRun >= 24
}
