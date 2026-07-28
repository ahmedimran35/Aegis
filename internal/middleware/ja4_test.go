package middleware

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestComputeJA4_KnownClients(t *testing.T) {
	tests := []struct {
		name         string
		state        *tls.ConnectionState
		wantPrefix   string
		wantNonEmpty bool
	}{
		{
			name: "TLS 1.3 with SNI",
			state: &tls.ConnectionState{
				Version:            tls.VersionTLS13,
				CipherSuite:        tls.TLS_AES_128_GCM_SHA256,
				ServerName:         "example.com",
				NegotiatedProtocol: "h2",
			},
			wantPrefix:   "ja4-",
			wantNonEmpty: true,
		},
		{
			name: "TLS 1.2 no SNI",
			state: &tls.ConnectionState{
				Version:     tls.VersionTLS12,
				CipherSuite: tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				ServerName:  "",
			},
			wantPrefix:   "ja4-",
			wantNonEmpty: true,
		},
		{
			name:         "nil state returns empty",
			state:        nil,
			wantPrefix:   "",
			wantNonEmpty: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ComputeJA4(tt.state)
			if tt.wantNonEmpty {
				if !strings.HasPrefix(got, tt.wantPrefix) {
					t.Errorf("ComputeJA4() = %q, want prefix %q", got, tt.wantPrefix)
				}
				if len(got) < len(tt.wantPrefix)+8 {
					t.Errorf("ComputeJA4() = %q, want length >= %d", got, len(tt.wantPrefix)+8)
				}
			} else {
				if got != "" {
					t.Errorf("ComputeJA4() = %q, want empty", got)
				}
			}
		})
	}
}

func TestComputeJA4_Stable(t *testing.T) {
	state := &tls.ConnectionState{
		Version:            tls.VersionTLS13,
		CipherSuite:        tls.TLS_AES_128_GCM_SHA256,
		ServerName:         "test.example.com",
		NegotiatedProtocol: "h2",
	}
	got1 := ComputeJA4(state)
	got2 := ComputeJA4(state)
	if got1 != got2 {
		t.Errorf("ComputeJA4 not stable: %q != %q", got1, got2)
	}
}

func TestComputeJA4H(t *testing.T) {
	tests := []struct {
		name         string
		headers      []string
		wantNonEmpty bool
	}{
		{
			name:         "typical browser order",
			headers:      []string{"Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding", "Connection"},
			wantNonEmpty: true,
		},
		{
			name:         "single header",
			headers:      []string{"Host"},
			wantNonEmpty: true,
		},
		{
			name:         "empty",
			headers:      nil,
			wantNonEmpty: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRequestWithHeaders(tt.headers)
			got := ComputeJA4H(r)
			if tt.wantNonEmpty {
				if !strings.HasPrefix(got, "ja4h-") {
					t.Errorf("ComputeJA4H() = %q, want prefix ja4h-", got)
				}
				if len(got) < len("ja4h-")+8 {
					t.Errorf("ComputeJA4H() = %q, want length >= %d", got, len("ja4h-")+8)
				}
			} else {
				if got != "" {
					t.Errorf("ComputeJA4H() = %q, want empty", got)
				}
			}
		})
	}
}

func TestComputeJA4H_Stable(t *testing.T) {
	headers := []string{"Host", "User-Agent", "Accept"}
	r1 := newRequestWithHeaders(headers)
	r2 := newRequestWithHeaders(headers)
	if ComputeJA4H(r1) != ComputeJA4H(r2) {
		t.Error("ComputeJA4H not stable for same headers")
	}
}

func newRequestWithHeaders(names []string) *http.Request {
	r, _ := http.NewRequest("GET", "http://example.com/", nil)
	r.Header = http.Header{}
	for _, n := range names {
		r.Header.Add(n, "x")
	}
	return r
}

func TestJA4Middleware_SetsContext(t *testing.T) {
	var gotJA4, gotJA4H string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotJA4, _ = r.Context().Value(ja4HashKey{}).(string)
		gotJA4H, _ = r.Context().Value(ja4hHashKey{}).(string)
		w.WriteHeader(http.StatusOK)
	})
	h := JA4Middleware(nil)(next)
	req := newRequestWithHeaders([]string{"Host", "User-Agent", "Accept"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if gotJA4H == "" {
		t.Errorf("JA4Middleware did not set JA4-H context value")
	}
	if gotJA4 != "" {
		t.Logf("JA4 set despite no TLS: %s (unexpected)", gotJA4)
	}
}