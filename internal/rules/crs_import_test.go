package rules

import (
	"strings"
	"testing"
)

func TestImportCRS_SingleRule(t *testing.T) {
	text := `SecRule ARGS "@rx union\s+select" "id:942100,phase:2,block,severity:CRITICAL,msg:'SQL Injection'"`
	got := ImportCRS(text)
	if got.Skipped != 0 {
		t.Errorf("Skipped = %d, want 0", got.Skipped)
	}
	if len(got.Rules) != 1 {
		t.Fatalf("Rules count = %d, want 1", len(got.Rules))
	}
	r := got.Rules[0]
	if r.MatchType != "regex" {
		t.Errorf("MatchType = %q, want regex", r.MatchType)
	}
	if r.Action != "block" {
		t.Errorf("Action = %q, want block", r.Action)
	}
	if r.Severity != "critical" {
		t.Errorf("Severity = %q, want critical", r.Severity)
	}
	if r.Name != "sql-injection" {
		t.Errorf("Name = %q, want sql-injection", r.Name)
	}
}

func TestImportCRS_ContainsOperator(t *testing.T) {
	text := `SecRule REQUEST_HEADERS:User-Agent "@contains sqlmap" "id:913100,phase:1,log,severity:HIGH,msg:'SQLMap scanner'"`
	got := ImportCRS(text)
	if len(got.Rules) != 1 {
		t.Fatalf("Rules count = %d, want 1", len(got.Rules))
	}
	r := got.Rules[0]
	if r.MatchType != "contains" {
		t.Errorf("MatchType = %q, want contains", r.MatchType)
	}
	if r.Action != "log" {
		t.Errorf("Action = %q, want log", r.Action)
	}
	if r.Pattern != "sqlmap" {
		t.Errorf("Pattern = %q, want sqlmap", r.Pattern)
	}
}

func TestImportCRS_ChainedSkipped(t *testing.T) {
	text := `SecRule ARGS "@rx select" "id:1,phase:2,block,chain"
    SecRule &TX "< 5" "t:none"`
	got := ImportCRS(text)
	if got.Skipped == 0 {
		t.Error("expected chained rule to be skipped")
	}
}

func TestImportCRS_MalformedSkipped(t *testing.T) {
	text := `This is not a SecRule
SecRule BROKEN "no operator here" "id:1"
SecRule ARGS "@rx ok" "id:2,phase:2,log,severity:LOW,msg:'ok'"`
	got := ImportCRS(text)
	if len(got.Rules) != 1 {
		t.Errorf("Rules count = %d, want 1 (only the valid rule)", len(got.Rules))
	}
	if got.Skipped < 2 {
		t.Errorf("Skipped = %d, want >= 2", got.Skipped)
	}
	if len(got.Warnings) == 0 {
		t.Error("expected warnings for skipped rules")
	}
}

func TestImportCRS_CommentsIgnored(t *testing.T) {
	text := `# This is a comment
SecRule ARGS "@rx test" "id:3,phase:2,log,severity:MEDIUM,msg:'Test'"`
	got := ImportCRS(text)
	if len(got.Rules) != 1 {
		t.Errorf("Rules count = %d, want 1", len(got.Rules))
	}
}

func TestMapCRSSeverity(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"CRITICAL", "critical"},
		{"HIGH", "high"},
		{"MEDIUM", "medium"},
		{"LOW", "low"},
		{"INFORMATIONAL", "info"},
		{"unknown", "info"},
	}
	for _, tt := range tests {
		if got := mapCRSSeverity(tt.in); got != tt.want {
			t.Errorf("mapCRSSeverity(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSanitizeName(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"SQL Injection", "sql-injection"},
		{"XSS Attack", "xss-attack"},
		{"weird'name", "weirdname"},
		{strings.Repeat("a", 100), strings.Repeat("a", 64)},
	}
	for _, tt := range tests {
		got := sanitizeName(tt.in)
		if got != tt.want {
			t.Errorf("sanitizeName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}