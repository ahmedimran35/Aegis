// Package safego provides helpers for spawning goroutines that survive
// panics. Use safego.Go for any goroutine whose lifetime is bounded by
// the lifetime of an HTTP request — a panic must never crash the engine.
package safego

import (
	"log"
	"runtime/debug"
)

// Go runs fn in a new goroutine and recovers any panic, logging it with
// the supplied tag. Prefer this over a bare `go fn(...)` for any
// background work whose panic would otherwise be fatal.
func Go(tag string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("safego[%s]: panic recovered: %v\n%s", tag, r, debug.Stack())
			}
		}()
		fn()
	}()
}

// GoDebug is like Go but logs at debug level (and does not print a stack)
// for low-volume background goroutines.
func GoDebug(tag string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("safego[%s]: panic recovered: %v", tag, r)
			}
		}()
		fn()
	}()
}
