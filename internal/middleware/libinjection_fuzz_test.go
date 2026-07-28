package middleware

import (
	"strings"
	"testing"
)

func FuzzDetectSQLi(f *testing.F) {
	f.Add("' OR '1'='1")
	f.Add("; DROP TABLE users--")
	f.Add("UNION SELECT password FROM users")
	f.Add("admin'--")
	f.Add("1' AND '1'='1")
	f.Add("normal search query")
	f.Add("")
	f.Add(" ")
	f.Add(strings.Repeat("'", 1024))
	f.Add(strings.Repeat("\\", 100))

	f.Fuzz(func(t *testing.T, input string) {
		// Must not panic. Result is true/false; only stability check is no panic.
		_ = DetectSQLi(input)
	})
}

func FuzzDetectXSS(f *testing.F) {
	f.Add("<script>alert(1)</script>")
	f.Add("<img src=x onerror=alert(1)>")
	f.Add("javascript:alert(1)")
	f.Add("<svg/onload=alert(1)>")
	f.Add("normal text")
	f.Add("")
	f.Add(strings.Repeat("<", 1000))
	f.Add("\x00\x01\x02\x03<script>")

	f.Fuzz(func(t *testing.T, input string) {
		_ = DetectXSS(input)
	})
}

func FuzzTokenizeSQL(f *testing.F) {
	f.Add("SELECT * FROM users WHERE id = 1")
	f.Add("'; DROP TABLE x; --")
	f.Add("admin")
	f.Add("")
	f.Add(strings.Repeat("'", 500))

	f.Fuzz(func(t *testing.T, input string) {
		tokens := tokenizeSQL(input)
		// Each token must have non-empty text
		for _, tok := range tokens {
			if tok.text == "" {
				t.Errorf("token with empty text, type=%q", tok.typ)
			}
		}
	})
}