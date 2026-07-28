package middleware

import (
	"fmt"
	"strings"
	"sync"
)

// BOLASchema describes per-resource authorization rules loaded from OpenAPI or
// AsyncAPI spec. It replaces the previous hard-coded resource allowlist with a
// data-driven model.
//
// A schema entry scopes a path-prefix to a resource type and lists the
// auth-model:
//
//   - UserScoped: object is owned by a single user; access requires
//     claims.UserID == object owner, OR claims.Role == "admin".
//   - TenantScoped: object belongs to a tenant; access requires
//     claims.TenantID == object.TenantID.
//   - Public: read-only is allowed; write requires explicit role.
//   - Private: requires explicit admin role.
//
// Operators add entries via SetSchema / AddSchemaEntry. Empty path-map
// disables the check entirely (legacy behavior).
type BOLASchema struct {
	mu      sync.RWMutex
	entries map[string]SchemaEntry // path-prefix → entry
}

// SchemaEntry is one schema rule.
type SchemaEntry struct {
	ResourceName string
	Scope        SchemaScope
	PathPrefix   string
}

// SchemaScope is the auth-model for the resource.
type SchemaScope string

const (
	ScopeUserScoped    SchemaScope = "user"
	ScopeTenantScoped  SchemaScope = "tenant"
	ScopePublic        SchemaScope = "public"
	ScopePrivate       SchemaScope = "private"
)

var globalBOLASchema = &BOLASchema{entries: make(map[string]SchemaEntry)}

// SetBOLASchema replaces the entire schema map.
func SetBOLASchema(in map[string]SchemaEntry) {
	globalBOLASchema.mu.Lock()
	defer globalBOLASchema.mu.Unlock()
	globalBOLASchema.entries = make(map[string]SchemaEntry)
	for k, v := range in {
		globalBOLASchema.entries[k] = v
	}
}

// AddSchemaEntry adds a single entry (idempotent on path-prefix).
func AddSchemaEntry(entry SchemaEntry) {
	if entry.PathPrefix == "" || entry.ResourceName == "" {
		return
	}
	globalBOLASchema.mu.Lock()
	defer globalBOLASchema.mu.Unlock()
	if globalBOLASchema.entries == nil {
		globalBOLASchema.entries = make(map[string]SchemaEntry)
	}
	globalBOLASchema.entries[entry.PathPrefix] = entry
}

// ResolveSchema looks up the most specific path-prefix matching path. Returns
// nil when no entry applies (caller treats as legacy / not-applicable).
func ResolveSchema(path string) *SchemaEntry {
	globalBOLASchema.mu.RLock()
	defer globalBOLASchema.mu.RUnlock()
	if len(globalBOLASchema.entries) == 0 {
		return nil
	}
	// Most-specific match first: try exact match then progressively shorter
	// prefixes.
	for prefix, entry := range globalBOLASchema.entries {
		if prefix != "" && strings.HasPrefix(path, prefix) {
			e := entry
			return &e
		}
	}
	return nil
}

// CardinalityTracker counts distinct resource IDs accessed by a single
// (user, type, tenant) tuple within a sliding window. A cardinality spike
// above the configured threshold flags potential BOLA / scraping.
//
// Implementation: per-(user, type, tenant) TTL-keyed Redis set. Failure to
// read = log + skip (fail-OPEN on Redis outage is acceptable for stats, NOT
// for primary security gating — which lives in middleware/bola.go).
type CardinalityTracker struct {
	rdb       CardinalityBackend
	keyPrefix string
	threshold int
}

// CardinalityBackend is the subset of Redis used by the tracker. Lets tests
// inject an in-memory fake.
type CardinalityBackend interface {
	SAdd(ctx interface{}, key string, members ...interface{}) error
	Expire(ctx interface{}, key string, ttl interface{}) error
	SCard(ctx interface{}, key string) (int64, error)
}

// NewCardinalityTracker creates a tracker. Pass nil for rdb to disable.
func NewCardinalityTracker(rdb CardinalityBackend, threshold int) *CardinalityTracker {
	if rdb == nil {
		return &CardinalityTracker{keyPrefix: "bola:card:", threshold: threshold}
	}
	return &CardinalityTracker{rdb: rdb, keyPrefix: "bola:card:", threshold: threshold}
}

// Track returns (countAfter, spike bool). Callers should log + drop on error,
// never fail-CLOSED on cardinality tracking alone.
func (c *CardinalityTracker) Track(scopeKey, resourceID string) (int64, bool, error) {
	if c.rdb == nil {
		return 0, false, nil
	}
	key := c.keyPrefix + scopeKey
	if err := c.rdb.SAdd(nil, key, resourceID); err != nil {
		return 0, false, fmt.Errorf("sadd: %w", err)
	}
	if err := c.rdb.Expire(nil, key, nil); err != nil {
		return 0, false, fmt.Errorf("expire: %w", err)
	}
	count, err := c.rdb.SCard(nil, key)
	if err != nil {
		return 0, false, fmt.Errorf("scard: %w", err)
	}
	return count, count > int64(c.threshold), nil
}
