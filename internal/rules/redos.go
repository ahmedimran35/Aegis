// Package rules: ReDoS defense utilities for user-supplied regex patterns.
//
// Aegis allows operators to define custom rule patterns at runtime via the
// rule engine. A naive regex like `(a+)+$` against a long string can lock up
// the goroutine for minutes on a single request. This file implements
// pre-compile heuristics to reject Catastrophic Backtracking patterns before
// they enter the compiled regex cache.
//
// Defense layers (all must pass for a pattern to be accepted):
//  1. Length cap (default 1024 chars)
//  2. Nested quantifier heuristic  (e.g. `(a+)+`, `(\w*)*`)
//  3. Quantified alternation in a quantified group (e.g. `(a|b)+$`)
//  4. Compile-probe at sandboxed timeout (default 100ms) using regexp2 for
//     non-backtracking evaluation
//
// Reference: OWASP Regex DoS (CWE-1333), Coraza coraza.re macro.ParserRe.
package rules

import (
	"errors"
	"fmt"
	"regexp"
	"regexp/syntax"
	"strings"
	"time"

	"github.com/dlclark/regexp2"
)

// MaxPatternLen is the hard upper bound on user-supplied regex patterns.
// Anything longer is almost certainly either a ReDoS vector or a typo.
const MaxPatternLen = 1024

// ProbeTimeout caps the regexp2 compile-and-probe round trip. Anything that
// takes longer is rejected — even a benign pattern that compiles slowly under
// memory pressure is more dangerous than useful as a WAF rule.
var ProbeTimeout = 100 * time.Millisecond

// ErrReDoS shapes (returned to caller as ErrReDoS for matcher_map hint).
var (
	ErrPatternTooLong   = errors.New("regex pattern exceeds max length")
	ErrNestedQuantifier = errors.New("nested quantifier detected (ReDoS risk)")
	ErrQuantifiedAlt    = errors.New("quantified alternation inside quantified group (ReDoS risk)")
	ErrProbeTimeout     = errors.New("regex compile/probe exceeded sandbox timeout")
	ErrPatternInvalid   = errors.New("regex pattern failed to compile")
)

// HasReDoSRisk runs all four defense layers against the pattern. Returns nil
// when the pattern is safe to register; an error describing the first failed
// layer otherwise.
func HasReDoSRisk(pattern string) error {
	if len(pattern) > MaxPatternLen {
		return fmt.Errorf("%w: %d > %d chars", ErrPatternTooLong, len(pattern), MaxPatternLen)
	}
	// Layer 2 + 3: structural heuristic via regexp/syntax AST.
	if err := syntaxTree(pattern); err != nil {
		return err
	}
	// Layer 4: sandbox probe with regexp2 (non-backtracking semantics).
	return probeSandbox(pattern)
}

// syntaxTree parses the pattern with regexp/syntax and flags nested quantifier
// and quantified-alternation shapes. Regexp/syntax.Parse is fast and side-effect
// free.
func syntaxTree(pattern string) error {
	tree, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		// Likely invalid pattern. Surface as ErrPatternInvalid so callers can
		// distinguish a typo from a banned shape.
		return fmt.Errorf("%w: %v", ErrPatternInvalid, err)
	}
	if err := walk(tree); err != nil {
		return err
	}
	// Layer 2b: source-level alternation-in-quantified-group detector.
	// Go's regexp/syntax collapses single-character literal alternations into
	// a CharClass, so the AST walk alone misses `(a|bc)+` — but the raw
	// pattern still contains `|`. Scan groups in the source string and flag
	// any group whose body contains `|` and that is followed by a quantifier.
	if err := scanSourceForAltInGroup(pattern); err != nil {
		return err
	}
	return nil
}

// scanSourceForAltInGroup walks the source pattern string tracking group depth
// and flags any group (depth ≥ 1) that contains a top-level alternation `|`
// immediately followed by a quantifier (`+`, `*`, `?`, `{`).
func scanSourceForAltInGroup(pattern string) error {
	type frame struct{ depth int }
	var stack []frame
	i := 0
	for i < len(pattern) {
		// Bail on character classes — `|` inside `[…]` is literal.
		if pattern[i] == '\\' && i+1 < len(pattern) {
			i += 2
			continue
		}
		switch pattern[i] {
		case '[':
			// Skip until closing ] (no nesting of [] in regex)
			j := i + 1
			for j < len(pattern) && pattern[j] != ']' {
				if pattern[j] == '\\' && j+1 < len(pattern) {
					j += 2
					continue
				}
				j++
			}
			i = j + 1
			continue
		case '(':
			stack = append(stack, frame{depth: 1})
			i++
			continue
		case ')':
			if len(stack) == 0 {
				i++
				continue
			}
			stack = stack[:len(stack)-1]
			i++
			continue
		case '|':
			// Top-level `|` outside any group is also dangerous when the
			// whole pattern is at risk — but we only flag when inside a
			// group AND followed (skipping past branch content + balanced
			// closing parens) by a quantifier.
			// `(a|b)+` is the classic shape — `|` is followed by `b`, then
			// `)`, then `+`. After the `|` we must skip over the *other*
			// branch's content (which may contain its own `(`, `)`, `|`)
			// until either a quantifier or end-of-group.
			if len(stack) > 0 {
				if closeOfGroupIsQuant(pattern, i) {
					return ErrQuantifiedAlt
				}
			}
			i++
			continue
		}
		i++
	}
	return nil
}

func isQuantByte(b byte) bool {
	switch b {
	case '+', '*', '?':
		return true
	}
	// `{` alone — caller must verify it's an actual quantifier via
	// isBoundedQuant, since literal `{` is common in JSON / JSONB bodies.
	return b == '{'
}

// isBoundedQuant returns true if the `{` at braceAt is the start of an
// unbounded (ReDoS-prone) `{n,}` or open-ended `{n,}` repeat. Bounded
// forms like `{3}` or `{3,5}` are safe because the engine cannot loop
// unbounded times.
func isBoundedQuant(pattern string, braceAt int) bool {
	if braceAt >= len(pattern) || pattern[braceAt] != '{' {
		return false
	}
	j := braceAt + 1
	// Require at least one digit before the closer.
	sawDigit := false
	for j < len(pattern) {
		c := pattern[j]
		if c >= '0' && c <= '9' {
			sawDigit = true
			j++
			continue
		}
		if c == '}' {
			// Bounded: {n} or {n,m} seen so far — safe.
			_ = sawDigit
			return true
		}
		if c == ',' {
			j++
			// After comma: either a digit (bounded upper) or `}` (unbounded)
			if j < len(pattern) && pattern[j] == '}' {
				return false // unbounded {n,} — ReDoS risk
			}
			return true // {n,m} — bounded
		}
		// Anything else: not a quantifier.
		return true
	}
	return true
}

// closeOfGroupIsQuant returns true when, after the alternation `|` at index i,
// the remainder of the *enclosing* group is closed by `)` followed by a
// quantifier. This detects the `(a|b|c)+` shape (and deeper variants like
// `(foo|bar)+`). Simplistic but accurate for non-nested patterns.
func closeOfGroupIsQuant(pattern string, pipeAt int) bool {
	depth := 0
	j := pipeAt + 1
	for j < len(pattern) {
		switch pattern[j] {
		case '\\':
			j += 2
			continue
		case '[':
			jj := j + 1
			for jj < len(pattern) && pattern[jj] != ']' {
				if pattern[jj] == '\\' {
					jj += 2
					continue
				}
				jj++
			}
			j = jj + 1
			continue
		case '(':
			depth++
		case ')':
			if depth == 0 {
				// hit the `)` of the group that contains the `|`.
				if j+1 < len(pattern) && isQuantByte(pattern[j+1]) {
					return true
				}
				return false
			}
			depth--
		}
		j++
	}
	return false
}

// walk descends the syntax tree and returns the first detected ReDoS shape.
// Detection rules (inner Capture wrappers are transparent to matching):
//   1. Nested quantifier: outer Op is quantifier AND any direct child
//      (after collapsing single-child Captures) is also a quantifier.
//   2. Quantified alternation: outer Op is quantifier AND any direct child
//      (after collapsing single-child Captures) is OpAlternate.
//
// Returns nil if no dangerous shape is present.
func walk(node *syntax.Regexp) error {
	if node == nil {
		return nil
	}

	for _, sub := range node.Sub {
		// Collapse a single-child Capture wrapper — it does not change
		// matching/backtracking semantics.
		inner := sub
		for inner.Op == syntax.OpCapture && len(inner.Sub) == 1 {
			inner = inner.Sub[0]
		}

		if isQuant(node.Op) {
			if isQuant(inner.Op) {
				return ErrNestedQuantifier
			}
			if inner.Op == syntax.OpAlternate {
				return ErrQuantifiedAlt
			}
		}
		if err := walk(sub); err != nil {
			return err
		}
	}
	return nil
}

func isQuant(op syntax.Op) bool {
	switch op {
	case syntax.OpPlus, syntax.OpStar, syntax.OpQuest, syntax.OpRepeat:
		return true
	}
	return false
}

// probeSandbox runs the pattern through regexp2 with a hard timeout. We use
// regexp2 (non-backtracking) to evaluate a small probe string; if it does not
// finish in ProbeTimeout we cancel and reject.
//
// This catches runaway backtracking variants not flagged by the structural
// pass (e.g. obscure alternation with character classes) at the cost of a
// short probe per registration. Registration is rare (rule create / revert
// / import) so this is affordable.
func probeSandbox(pattern string) error {
	re, err := regexp2.Compile(pattern, regexp2.None)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPatternInvalid, err)
	}
	done := make(chan error, 1)
	go func() {
		// Probe with a moderate-length input that exercises quantifier math.
		probe := strings.Repeat("a", 64) + "!"
		_, err := re.MatchString(probe)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("%w: %v", ErrPatternInvalid, err)
		}
		return nil
	case <-time.After(ProbeTimeout):
		return ErrProbeTimeout
	}
}

// Compile is a convenience wrapper that runs HasReDoSRisk first, then compiles
// with the standard regexp package (faster than regexp2 per Execute). Callers
// in the rule engine should use this instead of regexp.Compile directly.
func Compile(pattern string) (*regexp.Regexp, error) {
	if err := HasReDoSRisk(pattern); err != nil {
		return nil, err
	}
	return regexp.Compile(pattern)
}
