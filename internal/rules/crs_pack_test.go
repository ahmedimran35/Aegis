package rules

import (
	"fmt"
	"strings"
	"testing"
)

// Compile one curated rule through HasReDoSRisk gate.
func TestCuratedCRSPackCleanReDoS(t *testing.T) {
	for _, r := range CuratedCRSPack {
		t.Run(fmt.Sprintf("rule-%d", r.ID), func(t *testing.T) {
			if r.Pattern == "" {
				t.Fatalf("rule %d has empty pattern", r.ID)
			}
			if err := HasReDoSRisk(r.Pattern); err != nil {
				t.Fatalf("rule %d pattern failed ReDoS gate: %v\npattern: %q", r.ID, err, r.Pattern)
			}
			// Compile must also succeed
			if _, err := Compile(r.Pattern); err != nil {
				t.Fatalf("rule %d compile failed: %v", r.ID, err)
			}
		})
	}
}

func TestCuratedCRSPackActions(t *testing.T) {
	seenIDs := map[int]bool{}
	for _, r := range CuratedCRSPack {
		if seenIDs[r.ID] {
			t.Errorf("duplicate rule ID %d", r.ID)
		}
		seenIDs[r.ID] = true
		if r.Severity == "" {
			t.Errorf("rule %d missing severity", r.ID)
		}
		if r.Msg == "" {
			t.Errorf("rule %d missing msg", r.ID)
		}
		if r.Action == "" {
			t.Errorf("rule %d missing action", r.ID)
		}
	}
}

// Sample attack: validate top patterns match the vectors they claim.
func TestCuratedCRSPackSample(t *testing.T) {
	cases := []struct {
		id   int
		path string
		body string
		want bool
	}{
		{942110, "/login", "user=admin' OR 1=1--", true},
		{941100, "/comment", "<script>alert(1)</script>", true},
		{932100, "/file.php", "page=php://input", true},
		{930100, "/api", "x=1|id", true},
		{953100, "/uploads", "../../etc/passwd", true},
		{941110, "/url", "javascript:alert(1)", true},
		{934100, "/xml", "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY x SYSTEM \"file:///etc/passwd\">]>", true},
		{921110, "/x", "before\x00after", true},
		{921100, "/x", "header\r\nX-Injected: yes", true},
	}
	for _, tc := range cases {
		var found *CRSRawRule
		for i, r := range CuratedCRSPack {
			if r.ID == tc.id {
				found = &CuratedCRSPack[i]
				break
			}
		}
		if found == nil {
			t.Errorf("rule %d missing from pack", tc.id)
			continue
		}
		re, err := Compile(found.Pattern)
		if err != nil {
			t.Errorf("rule %d compile: %v", tc.id, err)
			continue
		}
		haystack := tc.path + " " + tc.body
		matched := re.MatchString(haystack)
		if matched != tc.want {
			t.Errorf("rule %d on %q: want match=%v, got %v", tc.id, haystack, tc.want, matched)
		}
	}
}

// Validate that NONE of the curated patterns match a benign profile.
func TestCuratedCRSNoFalsePositiveBaseline(t *testing.T) {
	benign := []string{
		"GET /api/users/me HTTP/1.1",
		"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Accept: text/html,application/xhtml+xml",
		"Accept-Language: en-US,en;q=0.9",
		"Content-Type: application/json",
		`{"username":"alice","password":"hunter2"}`,
		"GET /blog/2026/01/hello-world HTTP/1.1",
		"POST /search HTTP/1.1",
		"q=how+to+center+a+div+in+css",
	}
	for _, r := range CuratedCRSPack {
		if r.Action != "block" {
			continue
		}
		re, err := Compile(r.Pattern)
		if err != nil {
			continue
		}
		for _, b := range benign {
			if re.MatchString(b) {
				t.Errorf("rule %d (%s) FP on benign %q", r.ID, strings.TrimSpace(r.Msg), b)
			}
		}
	}
}
