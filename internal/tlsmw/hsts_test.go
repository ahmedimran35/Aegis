package tlsmw

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHSTSHeader_Default(t *testing.T) {
	h := HSTSHeader(0, false, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if got := rec.Header().Get("Strict-Transport-Security"); got != "max-age=63072000" {
		t.Errorf("HSTS default: got %q want %q", got, "max-age=63072000")
	}
}

func TestHSTSHeader_Full(t *testing.T) {
	h := HSTSHeader(31536000, true, true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	want := "max-age=31536000; includeSubDomains; preload"
	if got := rec.Header().Get("Strict-Transport-Security"); got != want {
		t.Errorf("HSTS full: got %q want %q", got, want)
	}
}

func TestMaxBodyBytes_AllowsUnder(t *testing.T) {
	body := strings.Repeat("a", 100)
	h := MaxBodyBytes(1024)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf, _ := io.ReadAll(r.Body)
		if len(buf) != 100 {
			t.Errorf("expected 100 bytes, got %d", len(buf))
		}
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("POST", "/", bytes.NewReader([]byte(body)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestMaxBodyBytes_RejectsOver(t *testing.T) {
	h := MaxBodyBytes(10)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	req := httptest.NewRequest("POST", "/", bytes.NewReader([]byte(strings.Repeat("a", 100))))
	req.ContentLength = 100
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413, got %d", rec.Code)
	}
}

func TestSmugglingCheck_RejectsCLplusTE(t *testing.T) {
	h := SmugglingCheck(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("POST", "/", nil)
	req.Header.Set("Content-Length", "100")
	req.Header.Set("Transfer-Encoding", "chunked")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestSmugglingCheck_AllowsCLOnly(t *testing.T) {
	h := SmugglingCheck(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("POST", "/", nil)
	req.Header.Set("Content-Length", "100")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestSmugglingCheck_AllowsTEOnly(t *testing.T) {
	h := SmugglingCheck(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("POST", "/", nil)
	req.Header.Set("Transfer-Encoding", "chunked")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestSmugglingCheck_GETBypass(t *testing.T) {
	h := SmugglingCheck(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Content-Length", "100")
	req.Header.Set("Transfer-Encoding", "chunked")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET should bypass, got %d", rec.Code)
	}
}

func TestHTTPSRedirect(t *testing.T) {
	h := HTTPSRedirect("example.com")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("GET", "/foo", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMovedPermanently {
		t.Errorf("expected 301, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "https://example.com/foo" {
		t.Errorf("Location: got %q want %q", loc, "https://example.com/foo")
	}
}

func TestHTTPSRedirect_AllowACME(t *testing.T) {
	called := false
	h := HTTPSRedirect("example.com")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("GET", "/.well-known/acme-challenge/abc", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !called {
		t.Error("ACME challenge should pass through")
	}
}
