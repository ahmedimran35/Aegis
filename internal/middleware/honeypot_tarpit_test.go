package middleware

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestHoneypotTarpitHit(t *testing.T) {
	h := NewHoneypotTarpit(nil, []string{"/admin", "/wp-login"}, true)
	defer h.CleanupBlacklist()

	if !h.IsHoneypot("/admin") {
		t.Fatalf("/admin should match")
	}
	if !h.IsHoneypot("/wp-login.php") {
		t.Fatalf("/wp-login.php should match (prefix)")
	}
	if h.IsHoneypot("/api/users") {
		t.Fatalf("/api/users should not match")
	}

	h.recordAndBlock("1.2.3.4", httptest.NewRequest("GET", "/admin", nil))
	if !h.IsBlacklisted("1.2.3.4") {
		t.Fatalf("1.2.3.4 should be blacklisted after a hit")
	}
	if h.IsBlacklisted("5.6.7.8") {
		t.Fatalf("5.6.7.8 should NOT be blacklisted")
	}

	// Force the entry to be expired.
	if el, ok := h.blacklist["1.2.3.4"]; ok {
		el.Value.(*blacklistEntry).exp = time.Now().Add(-1 * time.Minute)
	}
	if h.IsBlacklisted("1.2.3.4") {
		t.Fatalf("expired blacklist should be cleared")
	}
}

func TestHoneypotTarpitDisabled(t *testing.T) {
	h := NewHoneypotTarpit(nil, []string{"/admin"}, false)
	if h.IsHoneypot("/admin") {
		t.Fatalf("disabled honeypot should never match")
	}
}

// TestClientIP verifies the honeypot blacklist keys on the actual TCP
// connection, NOT on a client-controlled XFF header. The previous test
// (which asserted the XFF first hop) was a security bug: an attacker
// could rotate XFF to bypass the blacklist. The new behavior uses
// RemoteAddr unless the connection is from a configured trusted proxy.
func TestClientIP(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.0.2.1:54321"
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8")
	got := clientIP(r)
	if got != "192.0.2.1" {
		t.Fatalf("clientIP must use RemoteAddr, not client-supplied XFF; got %q", got)
	}
}
