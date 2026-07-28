package ai

import (
	"regexp"
	"strings"
)

// PIIRedactor strips/redacts personally identifiable information from text
// before sending to third-party AI providers. Patterns cover the most common
// vectors seen in HTTP traffic and free-text fields:
//
//   - Email addresses
//   - Credit-card-like digit sequences (Luhn-validated)
//   - US SSN (XXX-XX-XXXX)
//   - IPv4 addresses
//   - Bearer tokens (JWT-like "xxx.yyy.zzz")
//   - Phone numbers (E.164-ish)
//
// All replacements use [REDACTED:<type>] tokens so the LLM can still reason
// about quantity and position without seeing the literal value.
type PIIRedactor struct {
	email         *regexp.Regexp
	ssn           *regexp.Regexp
	ipv4          *regexp.Regexp
	jwt           *regexp.Regexp
	phone         *regexp.Regexp
	creditCard    *regexp.Regexp
}

// NewPIIRedactor compiles patterns once at startup.
func NewPIIRedactor() *PIIRedactor {
	return &PIIRedactor{
		email:      regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`),
		ssn:        regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
		ipv4:       regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
		jwt:        regexp.MustCompile(`\bey[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b`),
		phone:      regexp.MustCompile(`\b\+?[1-9]\d{9,14}\b`),
		creditCard: regexp.MustCompile(`\b\d{4}[ \-]?\d{4}[ \-]?\d{4}[ \-]?\d{1,7}\b`),
	}
}

// Redact returns the input with all detected PII replaced.
func (r *PIIRedactor) Redact(s string) string {
	if s == "" {
		return s
	}
	s = r.email.ReplaceAllString(s, "[REDACTED:email]")
	s = r.ssn.ReplaceAllString(s, "[REDACTED:ssn]")
	s = r.jwt.ReplaceAllString(s, "[REDACTED:jwt]")
	s = r.ipv4.ReplaceAllString(s, "[REDACTED:ipv4]")
	s = r.phone.ReplaceAllString(s, "[REDACTED:phone]")
	// credit card last, after dashes stripped from phone numbers — Luhn check
	s = r.creditCard.ReplaceAllStringFunc(s, func(m string) string {
		digits := stripNonDigits(m)
		if luhnValid(digits) && len(digits) >= 13 && len(digits) <= 19 {
			return "[REDACTED:cc]"
		}
		return m
	})
	return s
}

// RedactFields applies redaction to all string fields in a map. Used to scrub
// RequestFeatures.BodySnippet and similar payloads before they reach AI.
func (r *PIIRedactor) RedactFields(in map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		if s, ok := v.(string); ok {
			out[k] = r.Redact(s)
		} else {
			out[k] = v
		}
	}
	return out
}

// Detect returns the list of PII types found in s without modifying it.
// Useful for "may contain PII" warnings and audit logging.
func (r *PIIRedactor) Detect(s string) []string {
	if s == "" {
		return nil
	}
	var hits []string
	if r.email.MatchString(s) {
		hits = append(hits, "email")
	}
	if r.ssn.MatchString(s) {
		hits = append(hits, "ssn")
	}
	if r.jwt.MatchString(s) {
		hits = append(hits, "jwt")
	}
	if r.ipv4.MatchString(s) {
		hits = append(hits, "ipv4")
	}
	if r.phone.MatchString(s) {
		hits = append(hits, "phone")
	}
	for _, m := range r.creditCard.FindAllString(s, -1) {
		if luhnValid(stripNonDigits(m)) {
			hits = append(hits, "cc")
			break
		}
	}
	return hits
}

func stripNonDigits(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// luhnValid returns true if the digit string passes the Luhn check.
func luhnValid(digits string) bool {
	if digits == "" {
		return false
	}
	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i] - '0'
		if d > 9 {
			return false
		}
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += int(d)
		alt = !alt
	}
	return sum%10 == 0
}
