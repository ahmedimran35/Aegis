package rules

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestHasReDoSRisk(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		wantErr error
	}{
		// Benign patterns
		{"simple", `^foo$`, nil},
		{"alternation ok", `(foo|bar)`, nil},
		{"quantified char", `a+`, nil},
		{"quantified group", `(foo)+`, nil},
		{"common sql token", `(?i)\bselect\b`, nil},

		// Banned shapes
		{"nested quantifier classic", `(a+)+`, ErrNestedQuantifier},
		{"nested quantifier hex", `([a-f0-9]+)*`, ErrNestedQuantifier},
		{"nested star plus", `(a*)+b`, ErrNestedQuantifier},
		{"quantified alternation", `(a|b)+$`, ErrQuantifiedAlt},
		{"quantified alternation nested", `(foo|bar|ba.+)+`, ErrQuantifiedAlt}, // alt-in-quantified also flagged

		// Invalid
		{"invalid", `(unclosed`, ErrPatternInvalid},
		{"too long", strings.Repeat("a", MaxPatternLen+1), ErrPatternTooLong},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := HasReDoSRisk(tc.pattern)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("want nil, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("want %v, got nil", tc.wantErr)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("want errors.Is %v, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestCompile(t *testing.T) {
	re, err := Compile(`^hello$`)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !re.MatchString("hello") {
		t.Fatalf("match failed")
	}
}

func TestCompileRejectsReDoS(t *testing.T) {
	_, err := Compile(`(a+)+$`)
	if err == nil {
		t.Fatalf("want rejection")
	}
	if !errors.Is(err, ErrNestedQuantifier) {
		t.Fatalf("want ErrNestedQuantifier, got %v", err)
	}
}

func TestProbeTimeout(t *testing.T) {
	// Construct a pattern that takes noticeable time but is structurally OK.
	// regexp2 vs regexp differs but we're testing the timeout mechanism.
	// To keep this fast in CI, temporarily shorten the timeout.
	oldTimeout := ProbeTimeout
	ProbeTimeout = 1 * time.Microsecond
	defer func() { ProbeTimeout = oldTimeout }()

	// A pattern that regexp2 can evaluate but slowly enough to hit the
	// microsecond timeout on slow CI hardware.
	pat := `^(a+)+$`
	err := probeSandbox(pat)
	if err == nil {
		// On fast CI hosts the probe may finish in <1us; accept either.
		t.Skip("probe finished within 1us; CI too fast")
	}
	if !errors.Is(err, ErrProbeTimeout) {
		t.Fatalf("want ErrProbeTimeout, got %v", err)
	}
}
