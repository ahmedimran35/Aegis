package middleware

import "context"

// RequestMetrics holds cross-middleware data for a single request.
// Created by logging middleware, written to by classify/rule middlewares.
type RequestMetrics struct {
	AIClassification string
	ThreatScore      float64
	RuleScore        int
	MatchedRules     []string
	BodyThreatScore  float64
	BodyFindings     []string
}

type metricsCtxKey string

const requestMetricsKey metricsCtxKey = "request_metrics"

// NewRequestContext creates a context with a fresh RequestMetrics pointer.
func NewRequestContext(ctx context.Context) (context.Context, *RequestMetrics) {
	m := &RequestMetrics{}
	return context.WithValue(ctx, requestMetricsKey, m), m
}

// MetricsFromContext retrieves the RequestMetrics pointer from context.
func MetricsFromContext(ctx context.Context) *RequestMetrics {
	if m, ok := ctx.Value(requestMetricsKey).(*RequestMetrics); ok {
		return m
	}
	return nil
}
