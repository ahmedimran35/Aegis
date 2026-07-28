package ai

import (
	"strings"
	"testing"
	"time"
)

// TestPIIRedactor_WorstCase exercises the PII redaction regex set
// against pathological inputs that historically triggered catastrophic
// backtracking or runaway allocation. I-1.
//
// Each test MUST complete in well under a second; we set 2s as a
// generous upper bound to catch a 100x regression.
func TestPIIRedactor_WorstCase(t *testing.T) {
	r := NewPIIRedactor()

	cases := []struct {
		name string
		in   string
	}{
		{
			name: "long alphanumeric phone-like input",
			in:   strings.Repeat("1", 10000),
		},
		{
			name: "many digits with hyphens",
			in:   strings.Repeat("1234567890-", 1000),
		},
		{
			name: "email-like alternating dots",
			in:   strings.Repeat("a.b.c@", 1000) + "x.com",
		},
		{
			name: "jwt-shaped tokens",
			in:   strings.Repeat("eyABCDEFGHI0123456789.eyABCDEFGHI0123456789.eyABCDEFGHI0123456789.", 200),
		},
		{
			name: "many ssn candidates",
			in:   strings.Repeat("123-45-6789 ", 1000),
		},
		{
			name: "credit-card-shaped chaos",
			in:   strings.Repeat("4111 1111 1111 1111 ", 200),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			done := make(chan struct{})
			var out string
			go func() {
				out = r.Redact(tc.in)
				close(done)
			}()
			select {
			case <-done:
				_ = out
			case <-time.After(2 * time.Second):
				t.Fatalf("Redact hung on input %s", tc.name)
			}
		})
	}
}

// TestPIIRedactor_NoBoundsOnReturn explicitly handles the case where the
// output is significantly larger than the input (e.g. when ReplaceAll
// produces many short tokens for a long input). The function should
// return within O(n).
func TestPIIRedactor_NoOutputExplosion(t *testing.T) {
	r := NewPIIRedactor()
	in := strings.Repeat("user@example.com ", 1000)
	out := r.Redact(in)
	if len(out) > len(in)+1024 {
		t.Fatalf("output size %d much larger than input %d", len(out), len(in))
	}
}
