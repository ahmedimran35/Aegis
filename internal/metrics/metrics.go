// Package metrics exposes Prometheus metrics for Aegis WAF.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
)

var (
	RequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "aegis_requests_total", Help: "Total requests processed"},
		[]string{"action"}, // allow/block/log
	)

	BlocksTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "aegis_blocks_total", Help: "Total blocks by reason"},
		[]string{"reason"},
	)

	RateLimitDrops = prometheus.NewCounter(
		prometheus.CounterOpts{Name: "aegis_rate_limit_drops_total", Help: "Rate limit drops"},
	)

	AIClassifyTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "aegis_ai_classify_total", Help: "AI classify requests"},
		[]string{"result"}, // hit/miss/error
	)

	AIClassifyErrors = prometheus.NewCounter(
		prometheus.CounterOpts{Name: "aegis_ai_classify_errors_total", Help: "AI classify errors"},
	)

	BruteForceLocks = prometheus.NewCounter(
		prometheus.CounterOpts{Name: "aegis_brute_force_locks_total", Help: "Account lockouts from brute force"},
	)

	RequestDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "aegis_request_duration_seconds",
			Help:    "Request handling duration",
			Buckets: prometheus.DefBuckets,
		},
	)

	RuleCount = prometheus.NewGauge(
		prometheus.GaugeOpts{Name: "aegis_rule_count", Help: "Number of active WAF rules"},
	)
)

func init() {
	prometheus.MustRegister(
		RequestsTotal, BlocksTotal, RateLimitDrops,
		AIClassifyTotal, AIClassifyErrors, BruteForceLocks,
		RequestDuration, RuleCount,
	)
}

// Handler returns the Prometheus HTTP handler.
func Handler() http.Handler {
	return promhttp.Handler()
}
