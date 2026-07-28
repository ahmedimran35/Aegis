package reputation

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	cachePrefix   = "rep:ip:"
	statsPrefix   = "rep:stats:"
	cacheTTL      = 1 * time.Hour
	apiBaseURL    = "https://api.abuseipdb.com/api/v2"
	topLookupsKey = "rep:top_lookups"
	maxTopEntries = 100
)

// Result holds the reputation data for an IP.
type Result struct {
	IP                 string  `json:"ip"`
	AbuseConfidenceScore int   `json:"abuse_confidence_score"`
	CountryCode        string  `json:"country_code"`
	ISP                string  `json:"isp"`
	UsageType          string  `json:"usage_type"`
	TotalReports       int     `json:"total_reports"`
	LastReportedAt     string  `json:"last_reported_at"`
	IsPublic           bool    `json:"is_public"`
}

// Stats holds aggregate reputation check statistics.
type Stats struct {
	IPsChecked    int64 `json:"ips_checked"`
	IPsBlocked    int64 `json:"ips_blocked"`
	CacheHits     int64 `json:"cache_hits"`
	CacheMisses   int64 `json:"cache_misses"`
	APIErrors     int64 `json:"api_errors"`
	CacheHitRate  float64 `json:"cache_hit_rate"`
}

// TopEntry represents an IP in the top lookups list.
type TopEntry struct {
	IP                   string    `json:"ip"`
	AbuseConfidenceScore int       `json:"abuse_confidence_score"`
	CountryCode          string    `json:"country_code"`
	ISP                  string    `json:"isp"`
	TotalReports         int       `json:"total_reports"`
	CheckedAt            time.Time `json:"checked_at"`
}

// Client is the AbuseIPDB reputation client.
type Client struct {
	rdb        *redis.Client
	apiKey     string
	httpClient *http.Client
	enabled    bool

	// Atomic counters for stats
	checked   atomic.Int64
	blocked   atomic.Int64
	cacheHits atomic.Int64
	cacheMiss atomic.Int64
	apiErrors atomic.Int64
	failOpens atomic.Int64 // M-5: count of requests allowed due to upstream reputation errors

	stopCh chan struct{}
	mu     sync.RWMutex
}

// Config holds the client configuration.
type Config struct {
	APIKey  string
	Enabled bool
	RDB     *redis.Client
}

// NewClient creates a new reputation client.
func NewClient(cfg Config) *Client {
	c := &Client{
		rdb:     cfg.RDB,
		apiKey:  cfg.APIKey,
		enabled: cfg.Enabled,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		stopCh: make(chan struct{}),
	}
	return c
}

// IsEnabled returns whether the reputation client is enabled.
func (c *Client) IsEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.enabled
}

// SetEnabled updates the enabled state.
func (c *Client) SetEnabled(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.enabled = enabled
}

// SetAPIKey updates the API key.
func (c *Client) SetAPIKey(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.apiKey = key
}

// Stop halts any background goroutines.
func (c *Client) Stop() {
	select {
	case <-c.stopCh:
	default:
		close(c.stopCh)
	}
}

// CheckIP looks up an IP's reputation, using cache first.
func (c *Client) CheckIP(ctx context.Context, ip string) (*Result, error) {
	c.mu.RLock()
	enabled := c.enabled
	c.mu.RUnlock()

	if !enabled {
		return nil, fmt.Errorf("reputation checking is disabled")
	}

	// Skip private IPs
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}
	if isPrivateIP(parsed) {
		return &Result{
			IP:                   ip,
			AbuseConfidenceScore: 0,
			CountryCode:          "LOCAL",
			ISP:                  "Private Network",
			UsageType:            "Private",
		}, nil
	}

	// Check cache
	cacheKey := cachePrefix + ip
	cached, err := c.rdb.Get(ctx, cacheKey).Result()
	if err == nil && cached != "" {
		c.cacheHits.Add(1)
		var result Result
		if json.Unmarshal([]byte(cached), &result) == nil {
			c.updateTopLookups(ctx, &result)
			return &result, nil
		}
	}

	c.cacheMiss.Add(1)

	// Call AbuseIPDB API
	result, err := c.fetchFromAPI(ctx, ip)
	if err != nil {
		c.apiErrors.Add(1)
		return nil, err
	}

	// Cache the result
	data, _ := json.Marshal(result)
	c.rdb.Set(ctx, cacheKey, string(data), cacheTTL)

	// Update stats
	c.checked.Add(1)

	// Track in top lookups sorted set
	c.updateTopLookups(ctx, result)

	return result, nil
}

// fetchFromAPI calls the AbuseIPDB check endpoint.
func (c *Client) fetchFromAPI(ctx context.Context, ip string) (*Result, error) {
	c.mu.RLock()
	apiKey := c.apiKey
	c.mu.RUnlock()

	if apiKey == "" {
		return nil, fmt.Errorf("AbuseIPDB API key not configured")
	}

	url := fmt.Sprintf("%s/check?ipAddress=%s&maxAgeInDays=90&verbose", apiBaseURL, ip)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Key", apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 429 {
		return nil, fmt.Errorf("AbuseIPDB rate limit exceeded (free tier: 1000/day)")
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("AbuseIPDB API returned status %d", resp.StatusCode)
	}

	var apiResp struct {
		Data struct {
			IPAddress          string `json:"ipAddress"`
			AbuseConfidenceScore int  `json:"abuseConfidenceScore"`
			CountryCode        string `json:"countryCode"`
			ISP                string `json:"isp"`
			UsageType          string `json:"usageType"`
			TotalReports       int    `json:"totalReports"`
			LastReportedAt     string `json:"lastReportedAt"`
			IsPublic           bool   `json:"isPublic"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("decode API response: %w", err)
	}

	return &Result{
		IP:                   apiResp.Data.IPAddress,
		AbuseConfidenceScore: apiResp.Data.AbuseConfidenceScore,
		CountryCode:          apiResp.Data.CountryCode,
		ISP:                  apiResp.Data.ISP,
		UsageType:            apiResp.Data.UsageType,
		TotalReports:         apiResp.Data.TotalReports,
		LastReportedAt:       apiResp.Data.LastReportedAt,
		IsPublic:             apiResp.Data.IsPublic,
	}, nil
}

// GetCached returns a cached result without making an API call.
func (c *Client) GetCached(ctx context.Context, ip string) (*Result, bool) {
	cacheKey := cachePrefix + ip
	cached, err := c.rdb.Get(ctx, cacheKey).Result()
	if err != nil || cached == "" {
		return nil, false
	}
	var result Result
	if json.Unmarshal([]byte(cached), &result) != nil {
		return nil, false
	}
	return &result, true
}

// updateTopLookups adds an entry to the top lookups sorted set.
func (c *Client) updateTopLookups(ctx context.Context, r *Result) {
	entry, _ := json.Marshal(TopEntry{
		IP:                   r.IP,
		AbuseConfidenceScore: r.AbuseConfidenceScore,
		CountryCode:          r.CountryCode,
		ISP:                  r.ISP,
		TotalReports:         r.TotalReports,
		CheckedAt:            time.Now(),
	})
	// Use timestamp as score for ordering (most recent first)
	c.rdb.ZAdd(ctx, topLookupsKey, redis.Z{
		Score:  float64(time.Now().Unix()),
		Member: string(entry),
	})
	// Trim to max entries
	c.rdb.ZRemRangeByRank(ctx, topLookupsKey, 0, -(maxTopEntries + 1))
}

// GetTopLookups returns the most recently checked IPs.
func (c *Client) GetTopLookups(ctx context.Context) ([]TopEntry, error) {
	members, err := c.rdb.ZRevRange(ctx, topLookupsKey, 0, 49).Result()
	if err != nil {
		return nil, err
	}
	var entries []TopEntry
	for _, m := range members {
		var e TopEntry
		if json.Unmarshal([]byte(m), &e) == nil {
			entries = append(entries, e)
		}
	}
	return entries, nil
}

// GetStats returns aggregate statistics.
func (c *Client) GetStats(ctx context.Context) Stats {
	hits := c.cacheHits.Load()
	misses := c.cacheMiss.Load()
	total := hits + misses
	var hitRate float64
	if total > 0 {
		hitRate = float64(hits) / float64(total) * 100
	}
	return Stats{
		IPsChecked:   c.checked.Load(),
		IPsBlocked:   c.blocked.Load(),
		CacheHits:    hits,
		CacheMisses:  misses,
		APIErrors:    c.apiErrors.Load(),
		CacheHitRate: hitRate,
	}
}

// IncrBlocked increments the blocked counter.
func (c *Client) IncrBlocked() {
	c.blocked.Add(1)
}

// IncrFailOpen increments the fail-open counter (M-5).
func (c *Client) IncrFailOpen() {
	c.failOpens.Add(1)
}

// FailOpens returns the number of fail-open events since process start.
func (c *Client) FailOpens() int64 {
	return c.failOpens.Load()
}

// isPrivateIP checks if an IP is private/loopback/link-local.
func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() || ip.IsUnspecified() {
		return true
	}
	metadataCIDRs := []string{
		"169.254.169.254/32",
		"fd00:ec2::254/128",
		"100.100.100.200/32",
	}
	for _, cidr := range metadataCIDRs {
		_, netBlock, _ := net.ParseCIDR(cidr)
		if netBlock != nil && netBlock.Contains(ip) {
			return true
		}
	}
	return false
}

// StartPeriodicCheck begins a background goroutine that periodically checks
// top attacking IPs from the stats:top_ips sorted set.
func (c *Client) StartPeriodicCheck(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 10 * time.Minute
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				c.checkTopIPs(ctx)
			case <-c.stopCh:
				return
			}
		}
	}()
	log.Printf("reputation: periodic check started (interval: %v)", interval)
}

// checkTopIPs fetches top attacking IPs from Redis and checks their reputation.
func (c *Client) checkTopIPs(ctx context.Context) {
	c.mu.RLock()
	enabled := c.enabled
	c.mu.RUnlock()
	if !enabled {
		return
	}

	// Get top 10 attacking IPs from the stats sorted set
	topIPs, err := c.rdb.ZRevRange(ctx, "stats:top_ips", 0, 9).Result()
	if err != nil || len(topIPs) == 0 {
		return
	}

	for _, ip := range topIPs {
		// Check if already cached
		if _, found := c.GetCached(ctx, ip); found {
			continue
		}

		// Rate limit: wait between API calls to respect free tier
		select {
		case <-time.After(2 * time.Second):
		case <-c.stopCh:
			return
		}

		result, err := c.CheckIP(ctx, ip)
		if err != nil {
			log.Printf("reputation: periodic check failed for %s: %v", ip, err)
			continue
		}

		if result.AbuseConfidenceScore > 0 {
			log.Printf("reputation: %s score=%d country=%s reports=%d",
				ip, result.AbuseConfidenceScore, result.CountryCode, result.TotalReports)
		}
	}
}
