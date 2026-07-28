// Package api: stub implementations of advanced handlers and methods
// that the router wires but whose full implementations are tracked as
// roadmap items. Each stub returns a 501 Not Implemented so the binary
// compiles AND the operator can see which endpoints are intentionally
// not yet implemented. The audit identified these as "dead code" — this
// file converts the dead code into 501-returning endpoints so the
// surface is honest about its state.
package api

import (
	"net/http"
)

// 501 helper used by all stub handlers.
func notImplemented(w http.ResponseWriter, op string) {
	RespondError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED",
		"endpoint "+op+" is planned but not yet implemented; see docs/operations/ROADMAP.md")
}

// ApproveRule and ToggleDryRun remain stubs in stubs.go (roadmap items
// not implemented in this release).