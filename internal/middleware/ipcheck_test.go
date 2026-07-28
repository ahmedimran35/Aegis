package middleware

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIsBlocked(t *testing.T) {
	_, cidr1, _ := net.ParseCIDR("10.0.0.0/8")
	_, cidr2, _ := net.ParseCIDR("192.168.1.100/32")

	checker := &IPChecker{
		blocked: []BlockedIP{
			{Network: cidr1, Reason: "test range", Source: "manual"},
			{Network: cidr2, Reason: "test ip", Source: "manual"},
		},
	}

	tests := []struct {
		ip      string
		blocked bool
	}{
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"192.168.1.100", true},
		{"192.168.1.1", false},
		{"8.8.8.8", false},
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		result := checker.IsBlocked(ip)
		if (result != nil) != tt.blocked {
			t.Errorf("IsBlocked(%s) = %v, want blocked=%v", tt.ip, result != nil, tt.blocked)
		}
	}
}

func TestIsBlockedExpired(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("10.0.0.0/8")
	past := time.Now().Add(-1 * time.Hour)

	checker := &IPChecker{
		blocked: []BlockedIP{
			{Network: cidr, Reason: "expired", Source: "manual", ExpiresAt: &past},
		},
	}

	// The in-memory check doesn't filter expired — the DB query does.
	// So an expired entry still in cache would be matched.
	// This is fine because loadBlockedIPs filters on SQL level.
	ip := net.ParseIP("10.0.0.1")
	if checker.IsBlocked(ip) == nil {
		t.Error("expected expired entry to still match in memory (DB filters on load)")
	}
}

func TestExtractIP(t *testing.T) {
	// Security fix: X-Real-IP is NOT trusted (client-controlled, spoofable)
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Real-IP", "1.2.3.4")
	ip := extractIP(req)
	// Should use RemoteAddr, not X-Real-IP
	if ip == nil || ip.String() != "192.0.2.1" { // httptest default RemoteAddr
		t.Errorf("extractIP ignoring X-Real-IP = %v, want 192.0.2.1", ip)
	}

	// Test RemoteAddr
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Header.Del("X-Real-IP")
	ip2 := extractIP(req2)
	if ip2 == nil || ip2.String() != "192.0.2.1" { // httptest default RemoteAddr
		t.Errorf("extractIP with RemoteAddr = %v, want 192.0.2.1", ip2)
	}
}

func TestMiddlewareBlocked(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("10.0.0.0/8")
	checker := &IPChecker{
		blocked: []BlockedIP{
			{Network: cidr, Reason: "test", Source: "manual"},
		},
	}

	var called bool
	handler := checker.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if called {
		t.Error("handler should not have been called for blocked IP")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestMiddlewareAllowed(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("10.0.0.0/8")
	checker := &IPChecker{
		blocked: []BlockedIP{
			{Network: cidr, Reason: "test", Source: "manual"},
		},
	}

	var called bool
	handler := checker.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "8.8.8.8:12345"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if !called {
		t.Error("handler should have been called for allowed IP")
	}
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}
