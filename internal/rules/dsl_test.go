package rules

import (
	"errors"
	"testing"
)

func TestParseDSLValid(t *testing.T) {
	src := `# comment, should be ignored

rule 1001 "SQLi tautology" on ARGS match rx "(?i:\\bor\\s+1=1\\b)" action block severity CRITICAL score 0.9
rule 1002 "Admin path" on REQUEST_URI match contains "/admin" action log
rule 1003 "Loopback only" on CLIENT_IP match ip "127.0.0.0/8" action block score 0.3
rule 1004 "POST body too large" on REQUEST_BODY match gt 10485760 action block
`
	rules, errs := ParseDSL(src)
	if len(errs) > 0 {
		t.Fatalf("errors: %v", errs)
	}
	if len(rules) != 4 {
		t.Fatalf("got %d rules, want 4", len(rules))
	}
	if rules[0].Action != "block" {
		t.Errorf("rule 0 action = %q", rules[0].Action)
	}
	if rules[2].Operand != "127.0.0.0/8" {
		t.Errorf("rule 2 operand = %q", rules[2].Operand)
	}
	if rules[3].Operand != "10485760" {
		t.Errorf("rule 3 operand = %q", rules[3].Operand)
	}
}

func TestParseDSLComments(t *testing.T) {
	rules, _ := ParseDSL("# only comment\n# more\n")
	if len(rules) != 0 {
		t.Fatalf("expected 0 rules from comments, got %d", len(rules))
	}
}

func TestParseDSLErrors(t *testing.T) {
	src := `notarule 1 "x" on y match contains "z" action block
rule abc "x" on y match contains "z" action block
rule 1 on y match contains "z" action block
`
	_, errs := ParseDSL(src)
	if len(errs) < 3 {
		t.Fatalf("expected 3+ errors, got %d: %v", len(errs), errs)
	}
}

func TestDSLValidateSafePattern(t *testing.T) {
	r := DSLRule{
		ID: 1, Msg: "x", Variable: "ARGS",
		Match: "rx", Operand: `(?i:\bor\s+1=1\b)`,
		Action: "block", Score: 0.5,
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("safe pattern should validate: %v", err)
	}
}

func TestDSLValidateUnsafePattern(t *testing.T) {
	r := DSLRule{
		ID: 1, Msg: "x", Variable: "ARGS",
		Match: "rx", Operand: `^(a+)+$`,
		Action: "block", Score: 0.5,
	}
	err := r.Validate()
	if err == nil || !errors.Is(err, ErrUnsafePattern) {
		t.Fatalf("expected ErrUnsafePattern, got %v", err)
	}
}

func TestDSLValidateAction(t *testing.T) {
	r := DSLRule{ID: 1, Msg: "x", Variable: "ARGS", Match: "contains", Operand: "x", Action: "evil", Score: 0.1}
	if err := r.Validate(); err == nil {
		t.Fatalf("expected invalid action error")
	}
}

func TestDSLValidateCIDR(t *testing.T) {
	r := DSLRule{ID: 1, Msg: "x", Variable: "ARGS", Match: "ip", Operand: "10", Action: "block", Score: 0.1}
	if err := r.Validate(); err == nil {
		t.Fatalf("expected CIDR error")
	}
}

func TestDSLToCRSRaw(t *testing.T) {
	d := DSLRule{ID: 7, Msg: "x", Variable: "ARGS", Match: "contains", Operand: "z", Action: "block", Severity: "HIGH", Score: 0.4}
	c := d.ToCRSRaw()
	if c.ID != 7 || c.Operator != "contains" || c.Action != "block" {
		t.Fatalf("convert mismatch: %+v", c)
	}
}

func TestParseDSLTokensNestedSpaces(t *testing.T) {
	src := `rule   42   "msg"   on   ARGS   match   contains   "hello world"   action   log`
	rules, errs := ParseDSL(src)
	if len(errs) != 0 {
		t.Fatalf("errs: %v", errs)
	}
	if len(rules) != 1 || rules[0].Operand != "hello world" {
		t.Fatalf("got %+v", rules)
	}
}
