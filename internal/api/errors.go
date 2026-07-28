package api

import (
	"crypto/rand"
	"encoding/hex"
	"log"
)

// safeError returns a generic error message for clients while logging
// the real error server-side WITH a request id that can be cross-
// referenced between the client and the log. The internal error and
// full message are never returned in the HTTP response body (CWE-209).
//
// P-FIX (L-1): a stable request id is generated per call and emitted in
// the structured log line, so an operator can grep for it when a user
// reports an opaque "internal error" response.
func safeError(err error, context string) string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	rid := hex.EncodeToString(b[:])
	log.Printf("api error [%s] rid=%s: %v", context, rid, err)
	return context + " failed. Reference id: " + rid
}
