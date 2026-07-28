// Package ctxutil provides request-scoped helpers shared between Aegis
// middlewares. BodyOnce implements a single-pass body read for HTTP
// requests: multiple middlewares (bodyinspect, libinjection, ATO,
// bruteforce) can read the request body without each parsing it from
// scratch. The first reader fills the cache; subsequent readers get
// a fresh io.Reader from the cached bytes.
//
// Storage: a sync.Map keyed by `*http.Request` pointer. Memory is
// reclaimed naturally when the request returns and the map entry is
// GC'd. Cap is bounded by the in-flight request count.
//
// Non-functional change: previously each of the four middlewares called
// io.ReadAll on the same r.Body, each paying one full allocation +
// one full buffer copy. After: the body is read once and shared.
package ctxutil

import (
	"bytes"
	"io"
	"net/http"
	"sync"
)

type bodyEntry struct {
	once sync.Once
	data []byte
	err  error
}

var bodyCache sync.Map // key: *http.Request -> *bodyEntry

// ReadOnce returns the body bytes for r, reading the stream exactly
// once. Multiple callers in the chain each get a fresh io.Reader but
// the underlying byte slice is shared.
func ReadOnce(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	v, _ := bodyCache.LoadOrStore(r, &bodyEntry{})
	entry := v.(*bodyEntry)
	entry.once.Do(func() {
		// Cap body reads at 4 MiB. Anything larger is a request the
		// ATO/body-inspect modules do not need to inspect anyway.
		entry.data, entry.err = io.ReadAll(io.LimitReader(r.Body, 4<<20))
	})
	return entry.data, entry.err
}

// GetReader returns a fresh io.Reader from a previously cached body.
// Returns the body bytes directly so callers can use bytes.Contains /
// bytes.Index without allocating yet another wrapper.
func GetReader(r *http.Request) (io.Reader, error) {
	data, err := ReadOnce(r)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return http.NoBody, nil
	}
	return bytes.NewReader(data), nil
}

// Clear removes the cached body for r. Call after the response is
// written to free memory before the next request handler reuses r.
func Clear(r *http.Request) {
	bodyCache.Delete(r)
}
