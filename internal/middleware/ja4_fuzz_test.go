package middleware

import (
	"crypto/tls"
	"net/http"
	"strings"
	"testing"
)

func FuzzComputeJA4(f *testing.F) {
	f.Add(uint16(tls.VersionTLS13), uint16(tls.TLS_AES_128_GCM_SHA256), "example.com", "h2")
	f.Add(uint16(tls.VersionTLS12), uint16(tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256), "", "")
	f.Add(uint16(0), uint16(0), "", "")
	f.Add(uint16(0xffff), uint16(0xffff), strings.Repeat("a", 1024), strings.Repeat("b", 1024))

	f.Fuzz(func(t *testing.T, version, cipher uint16, sni, alpn string) {
		state := &tls.ConnectionState{
			Version:            version,
			CipherSuite:        cipher,
			ServerName:         sni,
			NegotiatedProtocol: alpn,
		}
		got := ComputeJA4(state)
		if got != "" && !strings.HasPrefix(got, "ja4-") {
			t.Errorf("ComputeJA4 malformed: %q", got)
		}
	})
}

func FuzzComputeJA4H(f *testing.F) {
	f.Add("Host", "User-Agent", "", "")
	f.Add("Accept", "Accept-Language", "Accept-Encoding", "")
	f.Add("", "", "", "")
	f.Add(strings.Repeat("X-Custom-Header-", 50), "Host", "Accept", "")

	f.Fuzz(func(t *testing.T, n1, n2, n3, n4 string) {
		r, _ := http.NewRequest("GET", "http://example.com/", nil)
		r.Header = http.Header{}
		for _, n := range []string{n1, n2, n3, n4} {
			if n != "" {
				r.Header.Add(n, "x")
			}
		}
		got := ComputeJA4H(r)
		if len(r.Header) == 0 {
			if got != "" {
				t.Errorf("ComputeJA4H on empty headers = %q, want empty", got)
			}
		} else {
			if !strings.HasPrefix(got, "ja4h-") {
				t.Errorf("ComputeJA4H malformed: %q", got)
			}
		}
	})
}