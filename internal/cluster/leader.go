// Package cluster: leader election via Redis SET NX EX.
//
// This file adds a lightweight leader-election primitive for Aegis rule
// writes (P7-F8). When multiple Aegis nodes run, only the leader may
// apply rule mutations; followers forward or read-only.
//
// Trade-offs:
//   - Simple: 4 lines of Redis (SET NX EX + Lua-based release that
//     verifies the caller holds the lock). No Raft consensus, no leader
//     log, no snapshot streaming.
//   - Sufficient for "only one writer at a time" semantics needed by
//     the rule store.
//   - For HA + quorum (split-brain avoidance under network partition),
//     use the existing internal/cluster/raft.go.
//
// P-FIX (M-24/M-47): cluster deployment notes — every Aegis node must
// share the SAME JWT signing secret (cfg.Auth.JWTSecret) AND the SAME
// TOTP AES key (AEGIS_TOTP_KEY) AND the SAME webhook signing master
// key (AEGIS_WEBHOOK_MASTER_KEY). These values are NEVER distributed
// through Redis or any node-to-node channel — operators MUST provision
// them via an external secret manager (Vault, AWS Secrets Manager, GCP
// Secret Manager, Kubernetes external-secrets, etc.) and surface them
// to each pod via env vars. Failure modes:
//
//   - If a single node starts with a divergent JWT secret, tokens
//     minted on it will be rejected on every other node and vice
//     versa. The cmd/waf-engine runtime intentionally refuses to start
//     with placeholders or low-entropy values (see config.Validate).
//   - If TOTP keys diverge, a user enrolling on one node will not be
//     able to log in on another.
//   - If webhook master keys diverge, downstream consumers will
//     silently fail signature verification.
//
// Operators are encouraged to set AEGIS_CLUSTER_PEER_URLS so the
// runtime can do an end-to-end sanity check that the secrets agree
// across nodes (env var supported but no enforcement as of v1.0).
package cluster

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

// LeaderStore is the minimal Redis surface used by leader election. The
// concrete *redis.Client satisfies this; tests can substitute a fake.
type LeaderStore interface {
	SetNX(ctx context.Context, key, value string, ttl time.Duration) (bool, error)
	Get(ctx context.Context, key string) (string, error)
	// RunScript runs a named script and returns the raw reply. Used for
	// the renew/release Lua snippets that need GET-then-act atomicity.
	RunScript(ctx context.Context, name string, keys []string, args ...interface{}) (interface{}, error)
}

// leaderKey is the Redis key for the cluster-wide leader lock.
const leaderKey = "aegis:cluster:leader"

// ErrNotLeader is returned when an operation requires leader status but
// the caller is not the current leader.
var ErrNotLeader = errors.New("cluster: caller is not leader")

// AcquireLeader attempts to become the cluster leader. Returns (true, nil)
// on success, (false, nil) if another node already holds the lease, or
// (false, err) on store failure. The TTL controls how long the lease is
// held before the caller must renew via RenewLeader.
func AcquireLeader(ctx context.Context, store LeaderStore, nodeID string, ttl time.Duration) (bool, error) {
	if store == nil || nodeID == "" {
		return false, errors.New("cluster: invalid args")
	}
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return store.SetNX(ctx, leaderKey, nodeID, ttl)
}

// RenewLeader extends the leader's lease if-and-only-if the caller still
// holds it. Returns ErrNotLeader if another node now owns the lease.
func RenewLeader(ctx context.Context, store LeaderStore, nodeID string, ttl time.Duration) error {
	if store == nil || nodeID == "" {
		return errors.New("cluster: invalid args")
	}
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	res, err := store.RunScript(ctx, "renew", []string{leaderKey},
		nodeID, ttl.Milliseconds())
	if err != nil {
		return err
	}
	if n, ok := res.(int); ok && n == 1 {
		return nil
	}
	if i64, ok := res.(int64); ok && i64 == 1 {
		return nil
	}
	return ErrNotLeader
}

// ReleaseLeader drops the leader lease if-and-only-if the caller holds it.
// Safe to call from any node; only the actual leader will successfully
// release.
func ReleaseLeader(ctx context.Context, store LeaderStore, nodeID string) error {
	if store == nil || nodeID == "" {
		return errors.New("cluster: invalid args")
	}
	_, err := store.RunScript(ctx, "release", []string{leaderKey}, nodeID)
	return err
}

// IsLeader reports whether nodeID is currently the cluster leader.
func IsLeader(ctx context.Context, store LeaderStore, nodeID string) (bool, error) {
	if store == nil || nodeID == "" {
		return false, errors.New("cluster: invalid args")
	}
	holder, err := store.Get(ctx, leaderKey)
	if errors.Is(err, errLeaderNotHeld) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return holder == nodeID, nil
}

var errLeaderNotHeld = errors.New("leader: not held")

// leaderRenewScript / leaderReleaseScript are the Lua snippets used by
// the production Redis adapter. Defined here so the adapter compiles
// them at init and re-uses the cached SHA on every call.
var (
	leaderRenewScript = redis.NewScript(`
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('PEXPIRE', KEYS[1], ARGV[2])
end
return 0
`)
	leaderReleaseScript = redis.NewScript(`
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0
`)
)

// RedisLeaderStore adapts a *redis.Client to the LeaderStore interface
// so callers can pass it directly to AcquireLeader / RenewLeader / etc.
type RedisLeaderStore struct {
	C *redis.Client
}

// SetNX wraps redis.Client.SetNX.
func (r *RedisLeaderStore) SetNX(ctx context.Context, key, value string, ttl time.Duration) (bool, error) {
	return r.C.SetNX(ctx, key, value, ttl).Result()
}

// Get wraps redis.Client.Get. Returns errLeaderNotHeld when the key is
// absent so IsLeader can collapse that case.
func (r *RedisLeaderStore) Get(ctx context.Context, key string) (string, error) {
	v, err := r.C.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return "", errLeaderNotHeld
	}
	return v, err
}

// RunScript routes to the right Lua script based on name. Names match
// the constants used in tests: "renew" and "release".
func (r *RedisLeaderStore) RunScript(ctx context.Context, name string, keys []string, args ...interface{}) (interface{}, error) {
	switch name {
	case "renew":
		return leaderRenewScript.Run(ctx, r.C, keys, args...).Result()
	case "release":
		return leaderReleaseScript.Run(ctx, r.C, keys, args...).Result()
	}
	return nil, errors.New("leader: unknown script " + name)
}