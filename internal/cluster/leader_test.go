package cluster

import (
	"context"
	"errors"
	"testing"
	"time"
)

// fakeStore is an in-memory LeaderStore for tests.
type fakeStore struct {
	kv      map[string]string
	expires map[string]time.Time
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		kv:      make(map[string]string),
		expires: make(map[string]time.Time),
	}
}

func (f *fakeStore) SetNX(ctx context.Context, key, value string, ttl time.Duration) (bool, error) {
	if exp, ok := f.expires[key]; ok && time.Now().After(exp) {
		delete(f.kv, key)
		delete(f.expires, key)
	}
	if _, exists := f.kv[key]; exists {
		return false, nil
	}
	f.kv[key] = value
	f.expires[key] = time.Now().Add(ttl)
	return true, nil
}

func (f *fakeStore) Get(ctx context.Context, key string) (string, error) {
	if exp, ok := f.expires[key]; ok && time.Now().After(exp) {
		delete(f.kv, key)
		delete(f.expires, key)
	}
	v, ok := f.kv[key]
	if !ok {
		return "", errLeaderNotHeld
	}
	return v, nil
}

func (f *fakeStore) RunScript(ctx context.Context, name string, keys []string, args ...interface{}) (interface{}, error) {
	switch name {
	case "renew":
		if f.kv[keys[0]] == args[0] {
			ms, _ := args[1].(int64)
			f.expires[keys[0]] = time.Now().Add(time.Duration(ms) * time.Millisecond)
			return int64(1), nil
		}
		return int64(0), nil
	case "release":
		if f.kv[keys[0]] == args[0] {
			delete(f.kv, keys[0])
			delete(f.expires, keys[0])
			return int64(1), nil
		}
		return int64(0), nil
	}
	return nil, errors.New("unknown script: " + name)
}

func TestAcquireLeader_InvalidArgs(t *testing.T) {
	ctx := context.Background()
	if _, err := AcquireLeader(ctx, nil, "node-a", 0); err == nil {
		t.Error("expected error for nil store")
	}
	if _, err := AcquireLeader(ctx, newFakeStore(), "", 0); err == nil {
		t.Error("expected error for empty nodeID")
	}
}

func TestAcquireLeader_FirstWins(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()

	ok, err := AcquireLeader(ctx, store, "node-a", 30*time.Second)
	if err != nil || !ok {
		t.Fatalf("AcquireLeader(node-a) = (%v, %v), want (true, nil)", ok, err)
	}

	// node-b retries
	ok2, err := AcquireLeader(ctx, store, "node-b", 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if ok2 {
		t.Error("node-b should not have acquired the lock")
	}

	leader, err := IsLeader(ctx, store, "node-a")
	if err != nil || !leader {
		t.Errorf("IsLeader(node-a) = (%v, %v), want (true, nil)", leader, err)
	}
	leader, err = IsLeader(ctx, store, "node-b")
	if err != nil || leader {
		t.Errorf("IsLeader(node-b) = (%v, %v), want (false, nil)", leader, err)
	}
}

func TestReleaseLeader(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	AcquireLeader(ctx, store, "node-a", 30*time.Second)

	// node-b cannot release node-a's lease
	if err := ReleaseLeader(ctx, store, "node-b"); err != nil {
		t.Fatalf("ReleaseLeader by non-holder err = %v", err)
	}
	leader, _ := IsLeader(ctx, store, "node-a")
	if !leader {
		t.Error("node-a should still be leader after node-b release attempt")
	}

	// node-a releases successfully
	if err := ReleaseLeader(ctx, store, "node-a"); err != nil {
		t.Fatalf("ReleaseLeader by holder err = %v", err)
	}
	leader, _ = IsLeader(ctx, store, "node-a")
	if leader {
		t.Error("node-a should no longer be leader after release")
	}

	// node-b can now acquire
	ok, _ := AcquireLeader(ctx, store, "node-b", 30*time.Second)
	if !ok {
		t.Error("node-b should acquire after release")
	}
}

func TestRenewLeader(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	AcquireLeader(ctx, store, "node-a", 30*time.Second)

	// node-b cannot renew
	if err := RenewLeader(ctx, store, "node-b", 60*time.Second); !errors.Is(err, ErrNotLeader) {
		t.Errorf("RenewLeader(node-b) = %v, want ErrNotLeader", err)
	}

	// node-a can renew
	if err := RenewLeader(ctx, store, "node-a", 60*time.Second); err != nil {
		t.Errorf("RenewLeader(node-a) = %v, want nil", err)
	}
}

func TestIsLeaderNotHeld(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	leader, err := IsLeader(ctx, store, "node-a")
	if err != nil {
		t.Fatalf("IsLeader err = %v, want nil", err)
	}
	if leader {
		t.Error("IsLeader with no holder should be false")
	}
}