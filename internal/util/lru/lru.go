// Package lru provides a small, generic LRU map. Used to bound the
// size of in-memory dictionaries that can otherwise be exhausted by
// an attacker rotating keys (IP addresses, JA3 hashes, etc).
package lru

import (
	"container/list"
	"sync"
)

// LRU is a goroutine-safe LRU map with a hard cap. When the map reaches
// the cap, inserting a new entry evicts the oldest one (the back of the
// list). All operations are O(1).
type LRU[K comparable, V any] struct {
	mu    sync.Mutex
	cap   int
	ll    *list.List
	items map[K]*list.Element
}

// entry pairs a key with its value for storage in the LRU list.
type entry[K comparable, V any] struct {
	key K
	val V
}

// New creates an LRU with the given capacity. cap is the maximum number
// of entries; inserting beyond it evicts the oldest.
func New[K comparable, V any](cap int) *LRU[K, V] {
	if cap <= 0 {
		cap = 1
	}
	return &LRU[K, V]{
		cap:   cap,
		ll:    list.New(),
		items: make(map[K]*list.Element),
	}
}

// Get returns the value for the key and a boolean reporting whether
// the key was present. Hits move the entry to the front (most-recently
// used).
func (l *LRU[K, V]) Get(key K) (V, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var zero V
	el, ok := l.items[key]
	if !ok {
		return zero, false
	}
	l.ll.MoveToFront(el)
	return el.Value.(*entry[K, V]).val, true
}

// Put inserts (or updates) key with value. If the LRU is at capacity
// the oldest entry is evicted to make room.
func (l *LRU[K, V]) Put(key K, value V) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if el, ok := l.items[key]; ok {
		el.Value.(*entry[K, V]).val = value
		l.ll.MoveToFront(el)
		return
	}
	el := l.ll.PushFront(&entry[K, V]{key: key, val: value})
	l.items[key] = el
	for l.ll.Len() > l.cap {
		oldest := l.ll.Back()
		if oldest == nil {
			break
		}
		l.ll.Remove(oldest)
		delete(l.items, oldest.Value.(*entry[K, V]).key)
	}
}

// Add increments value at key by delta, creating it at zero if absent.
// Returns the new value.
func (l *LRU[K, V]) Add(key K, delta V) V {
	l.mu.Lock()
	defer l.mu.Unlock()
	if el, ok := l.items[key]; ok {
		e := el.Value.(*entry[K, V])
		// arithmetic via interface{}; for V=int64/uint64/float64 we
		// rely on the caller using a numeric type. To keep this
		// dependency-free we special-case the common ones.
		switch n := any(&e.val).(type) {
		case *int64:
			*n += any(delta).(int64)
		case *int:
			*n += any(delta).(int)
		case *uint64:
			*n += any(delta).(uint64)
		}
		l.ll.MoveToFront(el)
		return e.val
	}
	var zero V
	v := zero
	switch n := any(&v).(type) {
	case *int64:
		*n = any(delta).(int64)
	case *int:
		*n = any(delta).(int)
	case *uint64:
		*n = any(delta).(uint64)
	}
	el := l.ll.PushFront(&entry[K, V]{key: key, val: v})
	l.items[key] = el
	for l.ll.Len() > l.cap {
		oldest := l.ll.Back()
		if oldest == nil {
			break
		}
		l.ll.Remove(oldest)
		delete(l.items, oldest.Value.(*entry[K, V]).key)
	}
	return v
}

// Len returns the current number of entries.
func (l *LRU[K, V]) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.ll.Len()
}

// Snapshot returns a copy of the map for read-only consumers.
func (l *LRU[K, V]) Snapshot() map[K]V {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make(map[K]V, len(l.items))
	for k, el := range l.items {
		out[k] = el.Value.(*entry[K, V]).val
	}
	return out
}

// Delete removes a key. No-op when absent.
func (l *LRU[K, V]) Delete(key K) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if el, ok := l.items[key]; ok {
		l.ll.Remove(el)
		delete(l.items, key)
	}
}

// IncBy is a convenience wrapper around Add for int64 maps: increments
// the counter at key by delta, inserting 0 if missing. Returns the new
// value. Provided because the common use case (per-IP counters) wants
// int64 specifically.
func (l *LRU[K, V]) IncBy(key K, delta V) V { return l.Add(key, delta) }
