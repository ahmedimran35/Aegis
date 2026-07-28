package tlsmw

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSmugglingAllowed(t *testing.T) {
	cases := []struct {
		name string
		cl   string
		te   string
	}{
		{"GET no headers", "", ""},
		{"POST CL only", "10", ""},
		{"POST chunked only", "", "chunked"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := makeReq("POST", tc.cl, tc.te)
			if err := detect(r); err != nil {
				t.Fatalf("expected pass, got %v", err)
			}
		})
	}
}

func TestSmugglingRejected(t *testing.T) {
	cases := []struct {
		name   string
		cl     string
		te     string
		expect string
	}{
		{"CL+chunked", "10", "chunked", "CL.TE"},
		{"CL non-numeric", "abc", "", "CL.non-numeric:abc"},
		{"CL zero + chunked", "0", "chunked", "CL.zero+TE"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := makeReq("POST", tc.cl, tc.te)
			err := detect(r)
			if err == nil {
				t.Fatalf("expected reject, got nil")
			}
			if !strings.Contains(err.Error(), tc.expect) {
				t.Fatalf("want vector=%s, got %v", tc.expect, err)
			}
		})
	}
}

// TestDuplicateCLSingleHeader splits per RFC 9112 duplicate CL within one
// header — different values separated by comma — must also reject.
func TestDuplicateCLSingleHeader(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	r.Header.Set("Content-Length", "10, 20")
	if err := detect(r); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("want duplicate reject, got %v", err)
	}
}

func TestDuplicateCLMultiHeader(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	r.Header.Add("Content-Length", "10")
	r.Header.Add("Content-Length", "20")
	if err := detect(r); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("want duplicate reject, got %v", err)
	}
}

// Vector 3 — Transfer-Encoding mixes chunked with another encoding.
func TestSmugglingMixedTE(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	r.Header.Set("Transfer-Encoding", "chunked, identity")
	if err := detect(r); err == nil {
		// RFC 9112 §6.1 permits "identity" but not mixed with other codings.
		// Pure "chunked, identity" is the RFC canonical; our detector flags
		// on a non-chunked + non-identity token, so this should PASS through.
		// Add a definitely-mixed encoding for negative test:
	}
	r2 := httptest.NewRequest("POST", "/", nil)
	r2.Header.Set("Transfer-Encoding", "chunked, gzip")
	if err := detect(r2); err == nil || !strings.Contains(err.Error(), "TE.mixed") {
		t.Fatalf("want TE.mixed:gzip reject, got %v", err)
	}
}

// Vector 5 — obfuscated TE via line folding (CR/LF embedded in field).
func TestSmugglingLineFoldTE(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	r.Header["Transfer-Encoding"] = []string{"chunk\r\ned"}
	if err := detect(r); err == nil || !strings.Contains(err.Error(), "TE.line-fold") {
		t.Fatalf("want TE.line-fold reject, got %v", err)
	}
}

// Vector 7 — h2c upgrade smuggling attempt.
func TestSmugglingH2CUpgrade(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	r.Header.Set("Upgrade", "h2c")
	r.Header.Set("Connection", "Upgrade")
	if err := detect(r); err == nil || !strings.Contains(err.Error(), "H2C.upgrade") {
		t.Fatalf("want H2C.upgrade reject, got %v", err)
	}
	// negative: only h2c without Connection: Upgrade should pass
	r2 := httptest.NewRequest("POST", "/", nil)
	r2.Header.Set("Upgrade", "h2c")
	if err := detect(r2); err != nil {
		t.Fatalf("h2c without Connection:Upgrade should pass, got %v", err)
	}
}

// Vector 8 — residual CL.TE when CL is non-numeric AND TE chunked present.
func TestSmugglingCLNonNumericWithTE(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	r.Header.Set("Content-Length", "abc")
	r.Header.Set("Transfer-Encoding", "chunked")
	err := detect(r)
	if err == nil {
		t.Fatalf("expected reject")
	}
	// either CLNonNumeric or CL.TE is an acceptable classification here
	if !strings.Contains(err.Error(), "CL.non-numeric") && !strings.Contains(err.Error(), "CL.TE") {
		t.Fatalf("want CL.* vector, got %v", err)
	}
}

func makeReq(method, cl, te string) *http.Request {
	r := httptest.NewRequest(method, "/", nil)
	if cl != "" {
		r.Header.Set("Content-Length", cl)
	}
	if te != "" {
		r.Header.Set("Transfer-Encoding", te)
	}
	return r
}
