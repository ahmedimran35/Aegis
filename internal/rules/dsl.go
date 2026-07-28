// Package rules: Aegis custom DSL.
//
// Grammar (line-oriented, JSON-free):
//
//   # comment
//   rule <id> "<msg>" on <variable> match rx "<pattern>" action block severity CRITICAL score 0.9
//   rule <id> "<msg>" on <variable> match contains "<literal>" action log
//   rule <id> "<msg>" on <variable> match ip "<cidr>" action block score 0.5
//   rule <id> "<msg>" on <variable> match gt <int> action block
//   rule <id> "<msg>" on <variable> match lt <int> action block
//
// All regex patterns pass through HasReDoSRisk before persistence; any
// pattern that fails the gate is rejected with ErrUnsafePattern.
package rules

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrUnsafePattern is returned when a regex pattern fails the ReDoS gate.
var ErrUnsafePattern = errors.New("pattern fails ReDoS gate")

// ErrParseDSL is returned for syntactic DSL errors.
type ErrParseDSL struct{ Line int; Reason string }

func (e *ErrParseDSL) Error() string {
	return fmt.Sprintf("dsl parse at line %d: %s", e.Line, e.Reason)
}

// DSLRule is one parsed rule from the Aegis DSL.
type DSLRule struct {
	ID        int
	Msg       string
	Variable  string
	Match     string // "rx" | "contains" | "ip" | "gt" | "lt"
	Operand   string // regex source / literal / cidr / integer
	Action    string // block | log | drop | deny
	Severity  string
	Score     float64
	Source    string // DSL text after stripping the `rule` keyword
}

// ParseDSL parses the Aegis DSL text into DSLRule entries. Comments (#) and
// blank lines are skipped. Returns the rules and a list of (line, reason)
// partial-error annotations for skipped lines.
func ParseDSL(text string) ([]DSLRule, []ErrParseDSL) {
	var (
		rules    []DSLRule
		problems []ErrParseDSL
	)
	for ln, raw := range strings.Split(text, "\n") {
		lineNum := ln + 1
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(strings.ToLower(line), "rule ") {
			problems = append(problems, ErrParseDSL{Line: lineNum, Reason: "missing 'rule' keyword"})
			continue
		}
		r, err := parseOne(line)
		if err != nil {
			if perr, ok := err.(*ErrParseDSL); ok {
				problems = append(problems, *perr)
			} else {
				problems = append(problems, ErrParseDSL{Line: lineNum, Reason: err.Error()})
			}
			continue
		}
		rules = append(rules, *r)
	}
	return rules, problems
}

// Validate enforces all invariants, including the ReDoS gate and supports
// the Operator → CuratedCRSPack-style conversion.
func (r *DSLRule) Validate() error {
	if r.ID <= 0 {
		return fmt.Errorf("id must be > 0, got %d", r.ID)
	}
	if r.Msg == "" {
		return fmt.Errorf("msg required")
	}
	if r.Variable == "" {
		return fmt.Errorf("variable required")
	}
	switch r.Action {
	case "block", "log", "drop", "deny":
	default:
		return fmt.Errorf("invalid action %q", r.Action)
	}
	switch r.Match {
	case "rx":
		if err := HasReDoSRisk(r.Operand); err != nil {
			return fmt.Errorf("%w: %v", ErrUnsafePattern, err)
		}
	case "contains":
		// no safety check beyond length
		if len(r.Operand) > 1024 {
			return fmt.Errorf("literal too long: %d", len(r.Operand))
		}
	case "ip":
		if !strings.Contains(r.Operand, "/") {
			return fmt.Errorf("ip expected CIDR, got %q", r.Operand)
		}
	case "gt", "lt":
		if _, err := strconv.Atoi(r.Operand); err != nil {
			return fmt.Errorf("gt/lt require integer, got %q", r.Operand)
		}
	default:
		return fmt.Errorf("unknown match operator %q", r.Match)
	}
	if r.Score < 0 || r.Score > 1 {
		return fmt.Errorf("score must be 0..1, got %f", r.Score)
	}
	return nil
}

// ToCRSRaw converts to CRSRawRule so DSL-defined rules can be merged with the
// curated pack at apply time.
func (r *DSLRule) ToCRSRaw() CRSRawRule {
	return CRSRawRule{
		ID:        r.ID,
		Severity:  r.Severity,
		Msg:       r.Msg,
		Variable:  r.Variable,
		Operator:  r.Match,
		Pattern:   r.Operand,
		Action:    r.Action,
		ScoreHint: r.Score,
	}
}

// parseOne parses a single `rule ...` line. Errors are typed *ErrParseDSL.
func parseOne(line string) (*DSLRule, error) {
	// Strip leading "rule " then tokenize.
	body := strings.TrimSpace(line[5:])
	if body == "" {
		return nil, &ErrParseDSL{Line: 0, Reason: "empty rule"}
	}
	r := &DSLRule{}

	toks, err := tokenizeDSL(body)
	if err != nil {
		return nil, err
	}
	// Walk: id, "msg", on, variable, match, <op>, operand, action, <act>, ...
	i := 0
	get := func() (string, error) {
		if i >= len(toks) {
			return "", &ErrParseDSL{Line: 0, Reason: "unexpected end of input"}
		}
		s := toks[i]
		i++
		return s, nil
	}

	// id (integer)
	idStr, err := get()
	if err != nil {
		return nil, err
	}
	id, err := strconv.Atoi(idStr)
	if err != nil {
		return nil, &ErrParseDSL{Line: 0, Reason: "id must be integer, got " + idStr}
	}
	r.ID = id

	// msg (quoted)
	if i >= len(toks) || toks[i][0] != '"' {
		return nil, &ErrParseDSL{Line: 0, Reason: "missing quoted msg"}
	}
	msg, ni, ok := readQuoted(toks[i:])
	if !ok {
		return nil, &ErrParseDSL{Line: 0, Reason: "unterminated msg quote"}
	}
	r.Msg = msg
	i += ni

	// on <variable>
	if tok, err := get(); err != nil || !strings.EqualFold(tok, "on") {
		return nil, &ErrParseDSL{Line: 0, Reason: "expected 'on'"}
	}
	v, err := get()
	if err != nil {
		return nil, err
	}
	r.Variable = v

	// match <op>
	if tok, err := get(); err != nil || !strings.EqualFold(tok, "match") {
		return nil, &ErrParseDSL{Line: 0, Reason: "expected 'match'"}
	}
	op, err := get()
	if err != nil {
		return nil, err
	}
	r.Match = strings.ToLower(op)

	switch r.Match {
	case "rx":
		if i >= len(toks) || toks[i][0] != '"' {
			return nil, &ErrParseDSL{Line: 0, Reason: "rx expected quoted pattern"}
		}
		pat, ni2, ok2 := readQuoted(toks[i:])
		if !ok2 {
			return nil, &ErrParseDSL{Line: 0, Reason: "rx pattern unterminated"}
		}
		r.Operand = pat
		i += ni2
	case "contains":
		if i >= len(toks) || toks[i][0] != '"' {
			return nil, &ErrParseDSL{Line: 0, Reason: "contains expected quoted literal"}
		}
		lit, ni2, ok2 := readQuoted(toks[i:])
		if !ok2 {
			return nil, &ErrParseDSL{Line: 0, Reason: "contains literal unterminated"}
		}
		r.Operand = lit
		i += ni2
	default:
		// ip / gt / lt: take next bare token. May be quoted for cleanliness.
		v2, err := get()
		if err != nil {
			return nil, err
		}
		if len(v2) >= 2 && v2[0] == '"' && v2[len(v2)-1] == '"' {
			v2 = v2[1 : len(v2)-1]
		}
		r.Operand = v2
	}

	// action <name> [severity X] [score N]
	if tok, err := get(); err != nil || !strings.EqualFold(tok, "action") {
		return nil, &ErrParseDSL{Line: 0, Reason: "expected 'action'"}
	}
	act, err := get()
	if err != nil {
		return nil, err
	}
	r.Action = strings.ToLower(act)

	if i < len(toks) && strings.EqualFold(toks[i], "severity") {
		i++
		if i < len(toks) {
			r.Severity = toks[i]
			i++
		}
	}
	if i < len(toks) && strings.EqualFold(toks[i], "score") {
		i++
		if i < len(toks) {
			s, err := strconv.ParseFloat(toks[i], 64)
			if err != nil {
				return nil, &ErrParseDSL{Line: 0, Reason: "score parse: " + err.Error()}
			}
			r.Score = s
			i++
		}
	}

	return r, nil
}

// tokenizeDSL splits a DSL body respecting double-quoted strings.
func tokenizeDSL(s string) ([]string, error) {
	var toks []string
	var cur strings.Builder
	inQ := false
	flush := func() {
		if cur.Len() > 0 {
			toks = append(toks, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			cur.WriteByte(c)
			inQ = !inQ
			if !inQ {
				flush()
			}
		case inQ:
			cur.WriteByte(c)
		case c == ' ' || c == '\t':
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	if inQ {
		return nil, &ErrParseDSL{Line: 0, Reason: "unterminated quote"}
	}
	return toks, nil
}

// readQuoted consumes a single quoted token from the front of toks. Returns
// the unquoted content and the number of tokens consumed.
func readQuoted(toks []string) (string, int, bool) {
	if len(toks) == 0 {
		return "", 0, false
	}
	t := toks[0]
	if len(t) < 2 || t[0] != '"' || t[len(t)-1] != '"' {
		return "", 0, false
	}
	return t[1 : len(t)-1], 1, true
}
