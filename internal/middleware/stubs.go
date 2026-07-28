// Package middleware: stub implementations of advanced middleware that
// are wired into the router pipeline but whose full implementations live
// in other modules (or are planned). Each stub is a no-op pass-through so
// the binary compiles and the pipeline stays functional; the production
// behavior is provided by follow-up work tracked in the audit roadmap.
package middleware

import (
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
)

// NewGRPCMiddleware now lives in grpc.go with full HTTP/2 frame parsing.
// This stub file remains only for the other unused-in-prod middlewares.

// MaxGRPCMessageSize now lives in grpc.go with real http.MaxBytesReader
// wrapping behavior.

// NewH2SettingsValidator rejects H2 SETTINGS frames with more than
// maxDistinct distinct header names. Stub: pass-through.
func NewH2SettingsValidator(_ int) *H2SettingsValidator {
	return &H2SettingsValidator{}
}

// H2SettingsValidator is a no-op holder so Middleware chaining compiles.
type H2SettingsValidator struct{}

// Middleware is a pass-through.
func (h *H2SettingsValidator) Middleware(next http.Handler) http.Handler { return next }

// NewH2ResetProtector limits H2 RST_STREAM frames per IP. Stub.
func NewH2ResetProtector(_ int, _ time.Duration) *H2ResetProtector {
	return &H2ResetProtector{}
}

// H2ResetProtector is a no-op holder.
type H2ResetProtector struct{}

// Middleware is a pass-through.
func (h *H2ResetProtector) Middleware(next http.Handler) http.Handler { return next }

// TracingMW is a no-op tracing middleware. The real implementation wraps
// every request in an OpenTelemetry span when otel.Default() is configured.
func TracingMW(next http.Handler) http.Handler { return next }

// ComputeH2 is reserved for HTTP/2 client fingerprinting. The stub
// returns the empty string.
func ComputeH2(_ http.ResponseWriter, _ *http.Request) string { return "" }

// NewMassAssignBlocker rejects mass-assignment attempts. The real
// implementation parses JSON bodies and strips unknown keys per a
// per-route allowlist. Stub: pass-through.
func NewMassAssignBlocker(_ any) *MassAssignBlocker {
	return &MassAssignBlocker{}
}

// MassAssignBlocker is a no-op holder.
type MassAssignBlocker struct{}

// Middleware is a pass-through.
func (m *MassAssignBlocker) Middleware(next http.Handler) http.Handler { return next }

// APIKeyRateLimit applies a per-API-key token-bucket rate limit. Stub
// implementation: pass-through. The production version lives in
// internal/auth/apikey_ratelimit.go (roadmap item).
func APIKeyRateLimit(_ *redis.Client, _ int) Middleware {
	return func(next http.Handler) http.Handler { return next }
}

// NewResponseFieldFilter blocks specific response fields. Stub.
func NewResponseFieldFilter(_ any) *ResponseFieldFilter {
	return &ResponseFieldFilter{}
}

// ResponseFieldFilter is a no-op holder.
type ResponseFieldFilter struct{}

// Middleware is a pass-through.
func (r *ResponseFieldFilter) Middleware(next http.Handler) http.Handler { return next }

// NewGraphQLAliasBlocker caps the number of GraphQL aliases per request.
// Stub: pass-through. Production: integrate with GraphQL middleware.
func NewGraphQLAliasBlocker(_ int) *GraphQLAliasBlocker {
	return &GraphQLAliasBlocker{}
}

// GraphQLAliasBlocker is a no-op holder.
type GraphQLAliasBlocker struct{}

// Middleware is a pass-through.
func (g *GraphQLAliasBlocker) Middleware(next http.Handler) http.Handler { return next }

// SSRFRedirectCheck validates redirect chains for SSRF. Stub.
func SSRFRedirectCheck(next http.Handler) http.Handler { return next }

// NewSessionIdle enforces per-user idle + absolute session timeouts.
// Stub: pass-through. The full implementation lives in
// internal/session/idle.go (roadmap item).
func NewSessionIdle(_ *redis.Client, _ time.Duration, _ time.Duration) *SessionIdle {
	return &SessionIdle{}
}

// SessionIdle is a no-op holder.
type SessionIdle struct{}

// Middleware is a pass-through.
func (s *SessionIdle) Middleware(next http.Handler) http.Handler { return next }