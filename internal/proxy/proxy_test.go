package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProxyForwardsRequest(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream", "true")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"upstream-ok"}`))
	}))
	defer upstream.Close()

	p, err := New(upstream.URL)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest("GET", "/test?foo=bar", nil)
	req.Header.Set("X-Custom", "value")
	w := httptest.NewRecorder()

	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	if w.Header().Get("X-Upstream") != "true" {
		t.Error("expected X-Upstream header from upstream")
	}

	body, _ := io.ReadAll(w.Body)
	if string(body) != `{"status":"upstream-ok"}` {
		t.Errorf("body = %q, want upstream response", string(body))
	}
}

func TestProxyUpstreamDown(t *testing.T) {
	p, err := New("http://localhost:19999")
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	p.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadGateway)
	}
}

func TestProxyInvalidURL(t *testing.T) {
	_, err := New("://invalid")
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}
