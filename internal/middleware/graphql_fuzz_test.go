package middleware

import (
	"encoding/json"
	"strings"
	"testing"
)

func FuzzCalculateDepth(f *testing.F) {
	f.Add("{ user { id name } }")
	f.Add("{ a { b { c { d } } } }")
	f.Add("query Q { x }")
	f.Add("")
	f.Add(strings.Repeat("{", 100))

	f.Fuzz(func(t *testing.T, query string) {
		d := calculateDepth(query)
		if d < 0 {
			t.Errorf("calculateDepth returned negative: %d for %q", d, query)
		}
		// Very deep nesting (1000+ braces) should not hang or panic.
		// No upper bound check — input is unbounded.
	})
}

func FuzzCalculateComplexity(f *testing.F) {
	f.Add("{ user { id name posts { title } } }")
	f.Add("query { a b c }")
	f.Add("")
	f.Add(strings.Repeat("x", 5000))

	f.Fuzz(func(t *testing.T, query string) {
		c := calculateComplexity(query)
		if c < 0 {
			t.Errorf("calculateComplexity returned negative: %d", c)
		}
	})
}

func FuzzExtractJSONStrings(f *testing.F) {
	f.Add([]byte(`{"key":"value"}`), "key")
	f.Add([]byte(`{"a":{"b":"c"}}`), "a.b")
	f.Add([]byte(`["x","y","z"]`), "[0]")
	f.Add([]byte(``), "")
	f.Add([]byte(`"not an object"`), "key")

	f.Fuzz(func(t *testing.T, data []byte, path string) {
		// data is fuzzed raw JSON; path is fuzzed string.
		var v interface{}
		if err := json.Unmarshal(data, &v); err != nil {
			return // invalid JSON, no crash
		}
		// Must not panic. May return nil or slice of strings.
		_ = extractJSONStrings(v, path)
	})
}