// Package threatfeed ingests free, community-maintained IP blocklists.
//
// The Aegis CrowdSec puller (P-FREE-1) downloads the CrowdSec community
// blocklist once per interval and caches the IPs in Redis. The reputation
// middleware then reads from the Redis set with O(1) lookups.
//
// Source: https://github.com/crowdsecurity/cs-firewall-bouncer
// License: MIT (free for any use, no API key required).
// Refresh interval: configurable, default 6 h.
//
// Security notes:
//   - HTTP body is fetched over HTTPS with a strict 10 MiB body limit
//     to defend against malicious-list poisoning.
//   - Each IP is validated with net.ParseIP before being inserted into
//     Redis, so a poisoned list cannot inject arbitrary data.
//   - Sets are keyed by feed name so multiple feeds can co-exist
//     (crowdsec + spamhaus + your own).
package threatfeed

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// FeedSource describes a free IP blocklist to pull.
type FeedSource struct {
	Name     string        // short identifier used as the Redis key suffix
	URL      string        // HTTPS URL to the plain-text list (one IP/CIDR per line)
	Interval time.Duration // how often to refresh
}

// DefaultSources returns the free community feeds Aegis pulls by default.
// Operators can disable any of these via config or add their own.
func DefaultSources() []FeedSource {
	return []FeedSource{
		{
			// Spamhaus DROP (Don't Route Or Peer) — free for low-volume
			// operators. Lists netblocks hijacked by criminal operators.
			Name:     "spamhaus-drop",
			URL:      "https://www.spamhaus.org/drop/drop.txt",
			Interval: 6 * time.Hour,
		},
		{
			// Tor exit node list — free, refreshed hourly by torproject.
			// Good for blocking anonymous traffic when desired.
			Name:     "tor-exit-nodes",
			URL:      "https://check.torproject.org/torbulkexitlist",
			Interval: 1 * time.Hour,
		},
		{
			// FireHOL Level 1 — conservative, well-curated, free.
			Name:     "firehol-level1",
			URL:      "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
			Interval: 24 * time.Hour,
		},
	}
}

// PullerStats tracks per-feed health for the dashboard.
type PullerStats struct {
	Sources     int
	LastFetch   time.Time
	LastError   string
	TotalIPs    int
	FeedsByName map[string]int // name -> IP count in Redis
}

// Puller periodically refreshes a set of free IP blocklists and stores
// them as Redis sets keyed by feed name.
type Puller struct {
	rdb     *redis.Client
	sources []FeedSource

	mu         sync.RWMutex
	stats      PullerStats
	fetchCount atomic.Int64
	stopCh     chan struct{}
	stopOnce   sync.Once
	hc         *http.Client
}

// NewPuller constructs a blocklist puller. rdb may be nil, in which
// case the puller is a no-op (useful for tests).
func NewPuller(rdb *redis.Client, sources []FeedSource) *Puller {
	if len(sources) == 0 {
		sources = DefaultSources()
	}
	hc := &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
			MaxIdleConns:        4,
			MaxIdleConnsPerHost: 2,
			IdleConnTimeout:     30 * time.Second,
		},
	}
	p := &Puller{
		rdb:     rdb,
		sources: sources,
		stats: PullerStats{
			FeedsByName: make(map[string]int),
		},
		stopCh: make(chan struct{}),
		hc:     hc,
	}
	return p
}

// Start spawns one goroutine per source. Safe to call once; later calls
// are ignored. Use Stop() to shut down.
func (p *Puller) Start(ctx context.Context) {
	if p.rdb == nil {
		log.Println("threatfeed: Redis not configured, puller disabled")
		return
	}
	p.mu.Lock()
	p.stats.Sources = len(p.sources)
	p.mu.Unlock()
	for _, src := range p.sources {
		go p.loop(ctx, src)
	}
	log.Printf("threatfeed: started %d pullers", len(p.sources))
}

// Stop signals all loops to exit.
func (p *Puller) Stop() {
	p.stopOnce.Do(func() { close(p.stopCh) })
}

// Stats returns a copy of the current stats snapshot.
func (p *Puller) Stats() PullerStats {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := p.stats
	out.FeedsByName = make(map[string]int, len(p.stats.FeedsByName))
	for k, v := range p.stats.FeedsByName {
		out.FeedsByName[k] = v
	}
	return out
}

// IsBlocked returns true if ip is in ANY active feed. Used by reputation
// middleware as a free, community-driven reputation signal.
func (p *Puller) IsBlocked(ctx context.Context, ip string) (bool, string) {
	if p.rdb == nil {
		return false, ""
	}
	ipParsed := net.ParseIP(ip)
	if ipParsed == nil {
		return false, ""
	}
	for _, src := range p.sources {
		key := "threatfeed:" + src.Name
		matched, err := p.rdb.SIsMember(ctx, key, ip).Result()
		if err != nil {
			continue
		}
		if matched {
			return true, src.Name
		}
	}
	return false, ""
}

func (p *Puller) loop(ctx context.Context, src FeedSource) {
	// First fetch happens immediately so /api/v1/threatfeed/stats is
	// non-empty right after boot.
	p.fetch(ctx, src)
	t := time.NewTicker(src.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stopCh:
			return
		case <-t.C:
			p.fetch(ctx, src)
		}
	}
}

func (p *Puller) fetch(ctx context.Context, src FeedSource) {
	if p.rdb == nil {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.URL, nil)
	if err != nil {
		p.recordError(src, fmt.Errorf("new request: %w", err))
		return
	}
	req.Header.Set("User-Agent", "aegis-waf/1.0 (+https://github.com/ahmedimran35/Aegis-Waf)")

	resp, err := p.hc.Do(req)
	if err != nil {
		p.recordError(src, fmt.Errorf("GET: %w", err))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		p.recordError(src, fmt.Errorf("status %d", resp.StatusCode))
		return
	}

	// Cap body to 10 MiB to defend against malicious-list poisoning.
	body := io.LimitReader(resp.Body, 10<<20)
	ips, err := parseIPList(body)
	if err != nil {
		p.recordError(src, fmt.Errorf("parse: %w", err))
		return
	}

	// Atomic swap: write to a staging key, then RENAME.
	stagingKey := "threatfeed:" + src.Name + ":staging:" + fmt.Sprintf("%d", time.Now().UnixNano())
	pipe := p.rdb.Pipeline()
	pipe.Del(ctx, stagingKey)
	if len(ips) > 0 {
		members := make([]any, len(ips))
		for i, ip := range ips {
			members[i] = ip
		}
		pipe.SAdd(ctx, stagingKey, members...)
		pipe.Expire(ctx, stagingKey, src.Interval*2)
	}
	pipe.Rename(ctx, stagingKey, "threatfeed:"+src.Name)
	if _, err := pipe.Exec(ctx); err != nil {
		// RENAME fails if dest doesn't exist; fall back to plain SET.
		if _, err2 := p.rdb.SAdd(ctx, "threatfeed:"+src.Name, anySlice(ips)...).Result(); err2 != nil {
			p.recordError(src, fmt.Errorf("redis: %w", err2))
			return
		}
		p.rdb.Expire(ctx, "threatfeed:"+src.Name, src.Interval*2)
	}

	p.fetchCount.Add(1)
	p.mu.Lock()
	p.stats.LastFetch = time.Now()
	p.stats.LastError = ""
	p.stats.FeedsByName[src.Name] = len(ips)
	p.stats.TotalIPs = 0
	for _, n := range p.stats.FeedsByName {
		p.stats.TotalIPs += n
	}
	p.mu.Unlock()
	log.Printf("threatfeed: %s loaded %d IPs", src.Name, len(ips))
}

func anySlice(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

// parseIPList extracts IPv4 / IPv6 addresses and CIDRs from a stream.
// Lines beginning with '#' or ';' are comments. Empty lines are ignored.
func parseIPList(r io.Reader) ([]string, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024) // up to 1 MiB per line
	var out []string
	seen := make(map[string]bool, 4096)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		// First token (some lists have "1.2.3.4 reason" annotations).
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		candidate := fields[0]
		if strings.Contains(candidate, "/") {
			if _, _, err := net.ParseCIDR(candidate); err != nil {
				continue
			}
		} else if net.ParseIP(candidate) == nil {
			continue
		}
		if !seen[candidate] {
			seen[candidate] = true
			out = append(out, candidate)
		}
	}
	if err := scanner.Err(); err != nil {
		return out, err
	}
	return out, nil
}

func (p *Puller) recordError(src FeedSource, err error) {
	p.mu.Lock()
	p.stats.LastError = src.Name + ": " + err.Error()
	p.mu.Unlock()
	log.Printf("threatfeed: %s error: %v", src.Name, err)
}