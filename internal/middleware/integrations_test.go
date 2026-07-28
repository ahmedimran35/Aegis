package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/user/waf/internal/auth"
)

func TestBehavioralBotScorer_Enabled(t *testing.T) {
	scorer := NewBehavioralBotScorer(BehavioralBotConfig{
		Enabled:        true,
		ScoreThreshold: 5,
		Action:         "challenge",
	}, nil)

	var called bool
	handler := scorer.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("handler should be called for allowed request")
	}
}

func TestBehavioralBotScorer_ScoreRequest(t *testing.T) {
	scorer := NewBehavioralBotScorer(BehavioralBotConfig{
		Enabled:        true,
		ScoreThreshold: 5,
	}, nil)

	tests := []struct {
		name    string
		ua      string
		accept  string
		lang    string
		wantMin int
		wantMax int
	}{
		{"empty UA scores", "", "", "", 3, 5},
		{"no headers scores", "Mozilla", "", "", 2, 5},
		{"full headers scores low", "Mozilla/5.0", "text/html", "en", 1, 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("User-Agent", tt.ua)
			if tt.accept != "" {
				req.Header.Set("Accept", tt.accept)
			}
			if tt.lang != "" {
				req.Header.Set("Accept-Language", tt.lang)
			}
			score := scorer.scoreRequest(req)
			if score < tt.wantMin || score > tt.wantMax {
				t.Errorf("scoreRequest() = %d, want [%d, %d]", score, tt.wantMin, tt.wantMax)
			}
		})
	}
}

func TestCSPNonceMiddleware_Enabled(t *testing.T) {
	mw := NewCSPNonceMiddleware(CSPNonceConfig{Enabled: true})

	var nonce string
	handler := mw.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce = CSPNonceFromContext(r)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if nonce == "" {
		t.Error("nonce should be set in context")
	}
	if len(nonce) != 32 {
		t.Errorf("nonce length = %d, want 32 (hex encoded 16 bytes)", len(nonce))
	}

	csp := w.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Error("CSP header should be set")
	}
	if nonce != "" && !containsSubstr(csp, nonce) {
		t.Error("CSP header should contain nonce")
	}
}

func TestCSPNonceMiddleware_Disabled(t *testing.T) {
	mw := NewCSPNonceMiddleware(CSPNonceConfig{Enabled: false})

	handlerCalled := false
	handler := mw.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !handlerCalled {
		t.Error("handler should be called when disabled")
	}
	if w.Header().Get("Content-Security-Policy") != "" {
		t.Error("CSP header should not be set when disabled")
	}
}

func TestBOLADetector_Enabled(t *testing.T) {
	detector := NewBOLADetector(BOLAConfig{Enabled: true}, nil)

	var handled bool
	handler := detector.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/users/123", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !handled {
		t.Error("handler should be called for GET request")
	}
}

func TestBOLADetector_Stats(t *testing.T) {
	detector := NewBOLADetector(DefaultBOLAConfig(), nil)
	stats := detector.Stats()

	if stats["enabled"] != true {
		t.Error("stats should show enabled")
	}
}

func TestBOLADetector_BlocksForeignUserResource(t *testing.T) {
	detector := NewBOLADetector(DefaultBOLAConfig(), nil)
	var called bool

	handler := detector.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/users/42", nil)
	claims := &auth.Claims{UserID: 7, Role: "viewer"}
	req = req.WithContext(auth.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if called {
		t.Error("handler should not be called for foreign user resource")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if detector.Stats()["flagged"].(int64) != 1 {
		t.Error("violation should be recorded")
	}
}

func TestCredentialStuffing_ParseJSONCredentials(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{"username":"alice","password":"secret"}`))
	req.Header.Set("Content-Type", "application/json")

	username, password, ok := extractLoginCredentials(req)
	if !ok {
		t.Fatal("expected credentials to be parsed")
	}
	if username != "alice" || password != "secret" {
		t.Errorf("credentials = %q/%q, want alice/secret", username, password)
	}

	restored, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != `{"username":"alice","password":"secret"}` {
		t.Errorf("body was not restored: %s", restored)
	}
}

func TestShadowAPIDiscovery_NormalizesEndpoints(t *testing.T) {
	if got := normalizeEndpointPath("/users/123/orders/456"); got != "/users/{id}/orders/{id}" {
		t.Errorf("normalizeEndpointPath() = %q", got)
	}
}

func containsSubstr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || findSubstring(s, sub))
}

func findSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
