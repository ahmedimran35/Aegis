package ai

import (
	"testing"
)

func TestExtractJSON(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"plain json", `{"score": 0.5}`, `{"score": 0.5}`},
		{"with code fence", "```json\n{\"score\": 0.5}\n```", `{"score": 0.5}`},
		{"with text around", `Here is the result: {"score": 0.5} hope that helps`, `{"score": 0.5}`},
		{"just fence", "```\n{\"score\": 0.5}\n```", `{"score": 0.5}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractJSON(tt.input)
			if got != tt.want {
				t.Errorf("extractJSON() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseClassification(t *testing.T) {
	raw := `{"score": 0.85, "classification": "malicious", "reasoning": "SQL injection attempt"}`
	c, err := parseClassification(raw)
	if err != nil {
		t.Fatalf("parseClassification() error: %v", err)
	}
	if c.Score != 0.85 {
		t.Errorf("score = %f, want 0.85", c.Score)
	}
	if c.Classification != "malicious" {
		t.Errorf("classification = %q, want malicious", c.Classification)
	}
}

func TestParseClassificationMalformed(t *testing.T) {
	c, err := parseClassification("not json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Classification != "benign" {
		t.Errorf("fallback classification = %q, want benign", c.Classification)
	}
}

func TestParseAnomalyResult(t *testing.T) {
	raw := `{"has_anomaly": true, "anomalies": [{"type": "traffic_spike", "severity": "high", "description": "10x normal traffic", "confidence": 0.95}]}`
	r, err := parseAnomalyResult(raw)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if !r.HasAnomaly {
		t.Error("expected has_anomaly=true")
	}
	if len(r.Anomalies) != 1 {
		t.Fatalf("anomalies count = %d, want 1", len(r.Anomalies))
	}
	if r.Anomalies[0].Type != "traffic_spike" {
		t.Errorf("type = %q, want traffic_spike", r.Anomalies[0].Type)
	}
}

func TestParseGeneratedRule(t *testing.T) {
	raw := `{"pattern": "(?i)union\\s+select", "match_type": "regex", "suggested_action": "block", "confidence": 0.9, "description": "SQL injection"}`
	r, err := parseGeneratedRule(raw)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if r.Pattern != `(?i)union\s+select` {
		t.Errorf("pattern = %q", r.Pattern)
	}
	if r.Confidence != 0.9 {
		t.Errorf("confidence = %f, want 0.9", r.Confidence)
	}
}

func TestParseAnalysisResult(t *testing.T) {
	raw := `{"summary": "Spike in traffic", "findings": ["10x requests from 1.2.3.4"], "suggestions": ["Block IP"]}`
	r, err := parseAnalysisResult(raw)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if r.Summary != "Spike in traffic" {
		t.Errorf("summary = %q", r.Summary)
	}
	if len(r.Findings) != 1 {
		t.Errorf("findings count = %d, want 1", len(r.Findings))
	}
}
