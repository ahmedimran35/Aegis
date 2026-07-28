package middleware

import (
	"math"
	"testing"
)

func TestShannonEntropy(t *testing.T) {
	if e := ShannonEntropy(""); e != 0 {
		t.Fatalf("empty entropy should be 0, got %f", e)
	}
	if e := ShannonEntropy("aaaa"); e > 0.0001 {
		t.Fatalf("uniform entropy should be near 0, got %f", e)
	}
	if e := ShannonEntropy("abcd1234"); e < 3 {
		t.Fatalf("varied entropy should be > 3, got %f", e)
	}
}

func TestIsURIRandom(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"/api/users", false},
		{"/api/orders/123", false},
		{"/../../etc/passwd", true}, // traversal
		{"/" + randHex(40), true},     // long hex
	}
	for _, tc := range cases {
		got := IsURIRandom(tc.in)
		if got != tc.want {
			t.Errorf("IsURIRandom(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestAdaptiveEvaluateHeaderAnomaly(t *testing.T) {
	a := NewAdaptiveDDoS(nil)
	// send 9 distinct UAs from same IP — exceeds >8 threshold
	for i := 0; i < 9; i++ {
		ua := []string{"Mozilla/5.0 bot", "curl/7.0", "wget/1.20", "Go-http-client/1.1", "python-requests/2", "libwww-perl/6", "Apache-HttpClient/4", "okhttp/4", "PostmanRuntime/7"}[i]
		a.Evaluate("1.2.3.4", "/api/x", ua, "", map[string][]string{
			"User-Agent": {ua},
		})
	}
	flags, reasons := a.Evaluate("1.2.3.4", "/api/x", "another/1", "", map[string][]string{
		"User-Agent": {"another/1"},
	})
	if !flags {
		t.Fatalf("expected flag (9 UAs + header anomaly), got %v", reasons)
	}
	if len(reasons) < 2 {
		t.Fatalf("expected ≥2 reasons, got %v", reasons)
	}
}

// helpers
func randHex(n int) string {
	const alphabet = "0123456789abcdef"
	out := make([]byte, n)
	for i := range out {
		out[i] = alphabet[int(math.Mod(float64(i*7+3), 16))]
	}
	return string(out)
}
func randLetters(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz"
	out := make([]byte, n)
	for i := range out {
		out[i] = alphabet[int(math.Mod(float64(i*13+5), 26))]
	}
	return string(out)
}
