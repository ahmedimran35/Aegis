package ai

import "context"

// AIService defines the interface for AI-powered Aegis capabilities.
type AIService interface {
	// ClassifyRequest evaluates an HTTP request for security threats.
	ClassifyRequest(ctx context.Context, features RequestFeatures) (*Classification, error)

	// DetectAnomaly analyzes traffic stats to find anomalies.
	DetectAnomaly(ctx context.Context, stats TrafficStats) (*AnomalyResult, error)

	// GenerateRule creates an Aegis rule from attack patterns.
	GenerateRule(ctx context.Context, attacks []AttackPattern) (*GeneratedRule, error)

	// AnalyzeLogs performs natural-language analysis on logs.
	AnalyzeLogs(ctx context.Context, query string) (*AnalysisResult, error)
}

// RequestFeatures holds extracted request data for classification.
type RequestFeatures struct {
	Method      string `json:"method"`
	Path        string `json:"path"`
	QueryParams string `json:"query_params"`
	ContentType string `json:"content_type"`
	UserAgent   string `json:"user_agent"`
	BodyHash    string `json:"body_hash"`
	BodySnippet string `json:"body_snippet,omitempty"`
	ClientIP    string `json:"client_ip"`
	Country     string `json:"country"`
	HeaderCount int    `json:"header_count"`
	ParamCount  int    `json:"param_count"`
}

// Classification is the result of AI request classification.
type Classification struct {
	Score          float64 `json:"score"`       // 0.0 to 1.0
	Classification string  `json:"classification"` // benign, suspicious, malicious
	Reasoning      string  `json:"reasoning"`
}

// TrafficStats holds aggregated traffic data for anomaly detection.
type TrafficStats struct {
	TotalRequests   int64            `json:"total_requests"`
	BlockedRequests int64            `json:"blocked_requests"`
	TopIPs          map[string]int64 `json:"top_ips"`
	TopEndpoints    map[string]int64 `json:"top_endpoints"`
	RequestsPerMin  float64          `json:"requests_per_min"`
	AvgThreatScore  float64          `json:"avg_threat_score"`
	TimeWindow      string           `json:"time_window"`
	// DegradedCycle is true when one or more Redis stats keys were missing
	// (redis.Nil). The detector should treat this as a fail-closed signal
	// to avoid emitting a fake-green anomaly.
	DegradedCycle bool `json:"degraded_cycle"`
}

// AnomalyResult is the output of anomaly detection.
type AnomalyResult struct {
	HasAnomaly  bool       `json:"has_anomaly"`
	Anomalies   []Anomaly  `json:"anomalies,omitempty"`
}

// Anomaly represents a single detected anomaly.
type Anomaly struct {
	Type        string  `json:"type"`        // traffic_spike, new_endpoint, pattern_shift, geo_anomaly
	Severity    string  `json:"severity"`    // low, medium, high, critical
	Description string  `json:"description"`
	Confidence  float64 `json:"confidence"`
}

// AttackPattern describes a cluster of attacks for rule generation.
type AttackPattern struct {
	Examples []string `json:"examples"`
	Category string   `json:"category"`
	Count    int      `json:"count"`
}

// GeneratedRule is an AI-suggested Aegis rule.
type GeneratedRule struct {
	Pattern       string  `json:"pattern"`
	MatchType     string  `json:"match_type"`
	SuggestedAction string `json:"suggested_action"`
	Confidence    float64 `json:"confidence"`
	Description   string  `json:"description"`
}

// AnalysisResult is the output of log analysis.
type AnalysisResult struct {
	Summary     string   `json:"summary"`
	Findings    []string `json:"findings"`
	Suggestions []string `json:"suggestions"`
}
