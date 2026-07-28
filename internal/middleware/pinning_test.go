package middleware

import (
	"testing"
)

func TestPinTableAddCheck(t *testing.T) {
	ResetViolations()
	SetPins(nil)
	pass, miss := CheckPin("example.com", "abc123")
	if !pass || miss {
		t.Fatalf("empty pins should pass, got pass=%v miss=%v", pass, miss)
	}

	SetPins(map[string][]string{
		"example.com": {"fp1", "fp2"},
	})
	pass, _ = CheckPin("example.com", "fp1")
	if !pass {
		t.Fatalf("fp1 should pass")
	}
	pass, _ = CheckPin("example.com", "fp2")
	if !pass {
		t.Fatalf("fp2 should pass")
	}
	pass, miss = CheckPin("example.com", "fp3")
	if pass {
		t.Fatalf("fp3 should fail")
	}
	if !miss {
		t.Fatalf("miss should be recorded")
	}
	if c := ViolationCount("example.com"); c != 1 {
		t.Fatalf("violation count = %d, want 1", c)
	}

	// Adding more pins composes, does not replace.
	AddPin("example.com", "fp3")
	pass, _ = CheckPin("example.com", "fp3")
	if !pass {
		t.Fatalf("fp3 should pass after AddPin")
	}
}

func TestParseClientHelloBytes(t *testing.T) {
	if ParseClientHelloBytes(nil) != nil {
		t.Fatalf("nil buf should return nil")
	}
	if ParseClientHelloBytes([]byte{0x16, 0x03, 0x03, 0x00, 0x05}) != nil {
		t.Fatalf("tiny buf should return nil")
	}
	// non-handshake record
	if ParseClientHelloBytes([]byte{0x17, 0x03, 0x03, 0x00, 0x05}) != nil {
		t.Fatalf("non-handshake should return nil")
	}
}

func TestJA4FromCaptureEmpty(t *testing.T) {
	if JA4FromCapture(nil) != "" {
		t.Fatalf("nil capture should return empty")
	}
	// empty struct → Version=0 → "00", SNI empty → "x", produces a real
	// (non-empty) ja4 string with 0 cipher/ext counts. Verify it's not the
	// nil-capture sentinel.
	out := JA4FromCapture(&ClientHelloCapture{})
	if out == "" {
		t.Fatalf("empty struct should produce a real ja4 hash")
	}
}

func TestStoreLookupForget(t *testing.T) {
	ForgetClientHello("k1")
	if LookupClientHello("k1") != nil {
		t.Fatalf("expected nil")
	}
	StoreClientHello("k1", &ClientHelloCapture{SNI: "example.com"})
	got := LookupClientHello("k1")
	if got == nil || got.SNI != "example.com" {
		t.Fatalf("expected SNI set; got %+v", got)
	}
	ForgetClientHello("k1")
	if LookupClientHello("k1") != nil {
		t.Fatalf("expected nil after forget")
	}
}
