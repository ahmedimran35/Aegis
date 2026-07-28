package rules

import (
	"net"
	"regexp"
	"testing"
)

func newTestEngine(rules []Rule) *Engine {
	// Pre-compile rules for testing without a DB
	for i := range rules {
		switch rules[i].MatchType {
		case MatchRegex:
			re, err := regexp.Compile(rules[i].Pattern)
			if err != nil {
				panic(err)
			}
			rules[i].compiled = re
		case MatchCIDR:
			_, n, _ := net.ParseCIDR(rules[i].Pattern)
			rules[i].network = n
		}
	}
	return &Engine{rules: rules}
}

func TestEvaluateRegexMatch(t *testing.T) {
	e := newTestEngine([]Rule{
		{ID: 1, Name: "sql-injection", Pattern: `(?i)(union\s+select|drop\s+table)`, MatchType: MatchRegex, Action: ActionBlock, Priority: 10},
	})

	result := e.Evaluate(net.ParseIP("1.2.3.4"), "GET", "/api/users", "id=1 union select 1", "curl/7.0", "", "", 4)
	if !result.Matched {
		t.Fatal("expected match")
	}
	if result.Action != ActionBlock {
		t.Errorf("action = %s, want block", result.Action)
	}
	if result.Rule.ID != 1 {
		t.Errorf("rule ID = %d, want 1", result.Rule.ID)
	}
}

func TestEvaluateStringMatch(t *testing.T) {
	e := newTestEngine([]Rule{
		{ID: 2, Name: "xss-attempt", Pattern: "<script>", MatchType: MatchString, Action: ActionBlock, Priority: 20},
	})

	result := e.Evaluate(net.ParseIP("1.2.3.4"), "POST", "/comment", "body=<script>alert(1)</script>", "Mozilla/5.0", "", "", 4)
	if !result.Matched {
		t.Fatal("expected match")
	}
	if result.Action != ActionBlock {
		t.Errorf("action = %s, want block", result.Action)
	}
}

func TestEvaluateCIDRMatch(t *testing.T) {
	e := newTestEngine([]Rule{
		{ID: 3, Name: "block-range", Pattern: "192.168.0.0/16", MatchType: MatchCIDR, Action: ActionBlock, Priority: 5},
	})

	// IP in range — should match
	result := e.Evaluate(net.ParseIP("192.168.1.100"), "GET", "/", "", "curl/7.0", "", "", 4)
	if !result.Matched {
		t.Fatal("expected match for CIDR")
	}

	// IP outside range — should not match
	result = e.Evaluate(net.ParseIP("10.0.0.1"), "GET", "/", "", "curl/7.0", "", "", 4)
	if result.Matched {
		t.Fatal("expected no match for IP outside CIDR")
	}
}

func TestEvaluateNoMatch(t *testing.T) {
	e := newTestEngine([]Rule{
		{ID: 1, Name: "sql-injection", Pattern: `(?i)(union\s+select)`, MatchType: MatchRegex, Action: ActionBlock, Priority: 10},
	})

	result := e.Evaluate(net.ParseIP("1.2.3.4"), "GET", "/api/users", "id=42", "Mozilla/5.0", "", "", 4)
	if result.Matched {
		t.Error("expected no match for benign request")
	}
}

func TestEvaluatePriorityOrder(t *testing.T) {
	// Rules arrive from DB sorted by priority ASC (lower number = higher priority)
	e := newTestEngine([]Rule{
		{ID: 20, Name: "high-pri", Pattern: `test`, MatchType: MatchString, Action: ActionBlock, Priority: 1},
		{ID: 10, Name: "low-pri", Pattern: `test`, MatchType: MatchString, Action: ActionLogOnly, Priority: 100},
	})

	result := e.Evaluate(net.ParseIP("1.2.3.4"), "GET", "/test", "", "", "", "", 4)
	if !result.Matched {
		t.Fatal("expected match")
	}
	// Priority 1 should match first (loaded first due to ORDER BY priority ASC)
	if result.Rule.ID != 20 {
		t.Errorf("rule ID = %d, want 20 (highest priority)", result.Rule.ID)
	}
}

func TestEvaluateStopOnFirstMatch(t *testing.T) {
	e := newTestEngine([]Rule{
		{ID: 1, Name: "allow-list", Pattern: "10.0.0.0/8", MatchType: MatchCIDR, Action: ActionAllow, Priority: 1},
		{ID: 2, Name: "block-all", Pattern: `.*`, MatchType: MatchRegex, Action: ActionBlock, Priority: 100},
	})

	// IP in allow list — first rule matches, stops
	result := e.Evaluate(net.ParseIP("10.0.0.1"), "GET", "/", "", "", "", "", 4)
	if !result.Matched || result.Action != ActionAllow {
		t.Errorf("expected allow, got matched=%v action=%s", result.Matched, result.Action)
	}
}

func TestCount(t *testing.T) {
	e := newTestEngine([]Rule{
		{ID: 1, Name: "a", Pattern: "a", MatchType: MatchString, Action: ActionBlock},
		{ID: 2, Name: "b", Pattern: "b", MatchType: MatchString, Action: ActionBlock},
	})
	if e.Count() != 2 {
		t.Errorf("Count() = %d, want 2", e.Count())
	}
}

func TestContainsIgnoreCase(t *testing.T) {
	tests := []struct {
		s, substr string
		want      bool
	}{
		{"Hello World", "hello", true},
		{"Hello World", "WORLD", true},
		{"Hello World", "xyz", false},
		{"", "", true},
		{"abc", "abcd", false},
	}
	for _, tt := range tests {
		got := containsIgnoreCase(tt.s, tt.substr)
		if got != tt.want {
			t.Errorf("containsIgnoreCase(%q, %q) = %v, want %v", tt.s, tt.substr, got, tt.want)
		}
	}
}

func TestEvaluateParanoiaFilter(t *testing.T) {
	e := newTestEngine([]Rule{
		{ID: 1, Name: "high-paranoia", Pattern: `bad`, MatchType: MatchString, Action: ActionBlock, ParanoiaLevel: 4},
		{ID: 2, Name: "low-paranoia", Pattern: `bad`, MatchType: MatchString, Action: ActionBlock, ParanoiaLevel: 1},
	})

	// Paranoia 1: only low-paranoia rule runs (ID 2 matches first by ID order).
	result := e.Evaluate(net.ParseIP("1.2.3.4"), "GET", "/bad", "", "", "", "", 1)
	if !result.Matched {
		t.Fatal("expected match at paranoia=1")
	}
	if result.Rule.ID != 2 {
		t.Errorf("paranoia=1 should match ID 2, got ID %d", result.Rule.ID)
	}

	// Paranoia 4: high-paranoia rule (ID 1) matches first.
	result = e.Evaluate(net.ParseIP("1.2.3.4"), "GET", "/bad", "", "", "", "", 4)
	if !result.Matched {
		t.Fatal("expected match at paranoia=4")
	}
	if result.Rule.ID != 1 {
		t.Errorf("paranoia=4 should match ID 1, got ID %d", result.Rule.ID)
	}
}
