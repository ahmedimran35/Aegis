package ai

import (
	"context"
	"testing"
)

func TestEvalHarnessNilRouter(t *testing.T) {
	h := NewEvalHarness(nil)
	cases := []EvalCase{{Name: "x", Path: "/", ExpectedLabel: "benign", ExpectedBlock: false}}
	ch := h.Run(context.Background(), cases)
	res := <-ch
	if res.Err == "" {
		t.Fatalf("expected error from nil router")
	}
	rep := h.Report()
	// With nil router, every case yields Err != "" so total=0 (since
	// total = correct+fp+fn excludes errors), and Errors=1. Verify the
	// error was recorded correctly.
	if rep.Errors != 1 {
		t.Fatalf("errors=%d, want 1", rep.Errors)
	}
	if rep.Total != 0 {
		t.Fatalf("total=%d, want 0 (errors-only path)", rep.Total)
	}
}

func TestPercentile(t *testing.T) {
	lats := []int64{10, 20, 30, 40, 50, 60, 70, 80, 90, 100}
	if got := percentile(lats, 50); got != 50 {
		t.Errorf("p50 = %d, want 50", got)
	}
	// p95 of 10 evenly-spaced values (linear interp) at index 9*95/100 = 8 → 90
	if got := percentile(lats, 95); got != 90 {
		t.Errorf("p95 = %d, want 90", got)
	}
	if got := percentile(nil, 50); got != 0 {
		t.Errorf("nil lats = %d, want 0", got)
	}
}

func TestLuhnValid(t *testing.T) {
	cases := map[string]bool{
		"4111111111111111": true,
		"4111-1111-1111-1111": true,
		"5500000000000004": true,
		"1234567890123456": false,
		"":                false,
		"4111111111111112": false,
	}
	for in, want := range cases {
		if got := luhnValid(stripNonDigits(in)); got != want {
			t.Errorf("luhn(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestPIIRedact(t *testing.T) {
	r := NewPIIRedactor()
	cases := map[string]string{
		"email me at jane@example.com please": "email me at [REDACTED:email] please",
		"ssn 123-45-6789 ok":                   "ssn [REDACTED:ssn] ok",
		"call +14155551234 today":              "call +[REDACTED:phone] today",
		"ip 192.168.1.1 detected":              "ip [REDACTED:ipv4] detected",
		"card 4111 1111 1111 1111 here":        "card [REDACTED:cc] here",
		"no pii here":                          "no pii here",
		"jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig_value_long_enough_to_match": "jwt [REDACTED:jwt]",
	}
	for in, want := range cases {
		if got := r.Redact(in); got != want {
			t.Errorf("redact(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPIIDetect(t *testing.T) {
	r := NewPIIRedactor()
	hits := r.Detect("jane@example.com 4111-1111-1111-1111 192.168.1.1")
	want := map[string]bool{"email": true, "cc": true, "ipv4": true}
	if len(hits) != len(want) {
		t.Fatalf("hits=%v want 3 unique", hits)
	}
	for _, h := range hits {
		if !want[h] {
			t.Errorf("unexpected hit %q", h)
		}
	}
}

func TestCostController(t *testing.T) {
	c := NewCostController()
	c.MaxTokensPerHour = 100
	c.MaxCallsPerMin = 3

	// First 3 calls succeed
	for i := 0; i < 3; i++ {
		if err := c.Allow(context.Background(), "u1", 10); err != nil {
			t.Fatalf("call %d unexpected err: %v", i, err)
		}
	}
	// 4th rejected (rate)
	if err := c.Allow(context.Background(), "u1", 10); err == nil {
		t.Fatalf("4th call should be rejected")
	}
	// Different user has separate budget
	if err := c.Allow(context.Background(), "u2", 10); err != nil {
		t.Fatalf("u2 first call rejected: %v", err)
	}
	// Saturate u2 tokens
	for i := 0; i < 10; i++ {
		_ = c.Allow(context.Background(), "u2", 10)
	}
	if err := c.Allow(context.Background(), "u2", 10); err == nil {
		t.Fatalf("u2 should be token-exhausted")
	}
}

func TestHashBodyStable(t *testing.T) {
	a := hashBody("hello")
	b := hashBody("hello")
	if a != b {
		t.Fatalf("hash unstable")
	}
	if hashBody("") != "" {
		t.Fatalf("empty body must return empty")
	}
}
