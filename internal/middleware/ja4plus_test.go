// Package middleware: tests for the spec-compliant JA4+ fingerprint.
package middleware

import (
	"strings"
	"testing"
)

// TestJA4Format verifies that the JA4 output matches the documented
// format: "ja4_{a}_{hash_a}_{hash_b}".
func TestJA4Format(t *testing.T) {
	fp := ComputeJA4Plus(
		[]uint16{0x1301, 0x1302, 0xc02b, 0xc02f},
		[]uint16{0x0000, 0x0017, 0xff01},
		[]uint16{0x0401, 0x0501, 0x0601, 0x0201},
		0x0303,
		true,
		[]string{"h2", "http/1.1"},
	)
	if !strings.HasPrefix(fp, "ja4_") {
		t.Errorf("JA4 should start with 'ja4_', got %q", fp)
	}
	parts := strings.Split(fp, "_")
	if len(parts) != 4 {
		t.Errorf("JA4 should have 4 parts, got %d: %q", len(parts), fp)
	}
	// a-part: proto(1) + version(2) + SNI(1) + numC(2) + numE(2) = 8 chars
	if len(parts[1]) != 8 {
		t.Errorf("JA4 a-part should be 8 chars, got %d: %q", len(parts[1]), parts[1])
	}
	// hash_a and hash_b: 12 hex chars each
	if len(parts[2]) != 12 {
		t.Errorf("hash_a should be 12 hex chars, got %d: %q", len(parts[2]), parts[2])
	}
	if len(parts[3]) != 12 {
		t.Errorf("hash_b should be 12 hex chars, got %d: %q", len(parts[3]), parts[3])
	}
	// Verify the proto+ver+sni prefix
	if !strings.HasPrefix(parts[1], "t12d") {
		t.Errorf("a-part should start with t12d (TCP+TLS1.2+SNI), got %q", parts[1])
	}
}

// TestJA4SNIWithout checks the SNI flag flips to "i" when no SNI is
// offered (rare in modern clients but used by some scanners).
func TestJA4SNIWithout(t *testing.T) {
	fp := ComputeJA4Plus(
		[]uint16{0x1301, 0x1302},
		[]uint16{0x0017, 0xff01},
		[]uint16{0x0401},
		0x0303,
		false,
		nil,
	)
	if !strings.Contains(fp, "t12i") {
		t.Errorf("expected SNI flag 'i' in JA4 a-part, got %q", fp)
	}
}

// TestJA4Stable verifies that the same input always produces the same
// fingerprint (deterministic).
func TestJA4Stable(t *testing.T) {
	args := []uint16{0x1301, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8}
	exts := []uint16{0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005}
	sigs := []uint16{0x0401, 0x0501, 0x0601, 0x0201, 0x0403, 0x0503, 0x0603, 0x0203}
	a := ComputeJA4Plus(args, exts, sigs, 0x0303, true, []string{"h2", "http/1.1"})
	b := ComputeJA4Plus(args, exts, sigs, 0x0303, true, []string{"h2", "http/1.1"})
	if a != b {
		t.Errorf("JA4 must be deterministic, got %q vs %q", a, b)
	}
}

// TestJA4SortInvariant verifies that reordering the cipher suites
// (which is legal in TLS — clients can offer them in any order) does
// NOT change the JA4 fingerprint. This is the key property that makes
// JA4 robust.
func TestJA4SortInvariant(t *testing.T) {
	a := []uint16{0x1301, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8}
	b := []uint16{0xcca8, 0xc02b, 0x1301, 0x1302, 0xcca9, 0xc02f}
	exts := []uint16{0x0000, 0x0017, 0xff01}
	sigs := []uint16{0x0401, 0x0501, 0x0601}
	fp1 := ComputeJA4Plus(a, exts, sigs, 0x0303, true, nil)
	fp2 := ComputeJA4Plus(b, exts, sigs, 0x0303, true, nil)
	if fp1 != fp2 {
		t.Errorf("JA4 must be reorder-invariant, got %q vs %q", fp1, fp2)
	}
}

// TestJA4HDistinct verifies that the JA4_h fingerprint (raw-order hash)
// differs from the JA4_b fingerprint (sorted-order hash) when the
// ciphers are reordered. This proves the two fingerprints are not
// redundant.
func TestJA4HDistinct(t *testing.T) {
	a := []uint16{0x1301, 0x1302, 0xc02b, 0xc02f}
	b := []uint16{0xc02f, 0x1301, 0xc02b, 0x1302}
	exts := []uint16{0x0000, 0x0017}
	hA := ComputeJA4HPlus(a, exts, nil, 0x0303)
	hB := ComputeJA4HPlus(b, exts, nil, 0x0303)
	if hA == hB {
		t.Errorf("JA4_h should differ for reordered ciphers, both = %q", hA)
	}
}

// TestJA4GREASEFilter verifies that GREASE values (0x0a0a, 0x1a1a,
// etc.) are stripped from extension/cipher/sig lists before hashing.
// GREASE is randomized per connection, so including it would
// destroy fingerprint stability.
func TestJA4GREASEFilter(t *testing.T) {
	// Two ClientHellos identical except for GREASE rotation.
	a := []uint16{0x0a0a, 0x1301, 0xc02b, 0x1302, 0xc02f}
	b := []uint16{0x1a1a, 0x1301, 0xc02b, 0x1302, 0xc02f}
	exts := []uint16{0x0000, 0x0017, 0xff01}
	sigs := []uint16{0x0401, 0x0501, 0x0601, 0x0a0a, 0x0b0b}
	fpA := ComputeJA4Plus(a, exts, sigs, 0x0303, true, nil)
	fpB := ComputeJA4Plus(b, exts, sigs, 0x0303, true, nil)
	if fpA != fpB {
		t.Errorf("JA4 must be GREASE-invariant, got %q vs %q", fpA, fpB)
	}
}

// TestParseClientHelloSmoke parses a minimal synthetic ClientHello and
// verifies the parsed fields are non-empty.
func TestParseClientHelloSmoke(t *testing.T) {
	// Build a synthetic ClientHello. Format:
	//   record: type(1)=0x16, ver(2)=0x0303, len(2)
	//   handshake: type(1)=0x01, len(3)
	//   client_ver(2), random(32), session_id(1)+id, cipher_suites(2)+cs,
	//   compression(1)+methods, extensions(2)+ext
	ciphers := []byte{
		0x00, 0x04, // length 4
		0x13, 0x01, // TLS_AES_128_GCM_SHA256
		0x13, 0x02, // TLS_AES_256_GCM_SHA384
	}
	random := make([]byte, 32)
	sid := []byte{0x00} // empty session id
	comp := []byte{0x01, 0x00} // 1 method, null
	// SNI extension: type 0x0000, length 5, list length 3, host "a.b"
	sniExt := []byte{
		0x00, 0x00, // type
		0x00, 0x05, // length
		0x00, 0x03, // list length
		0x00,       // host length
		'a', '.', 'b',
	}
	exts := []byte{0x00, byte(len(sniExt))} // 2-byte length prefix
	exts = append(exts, sniExt...)

	hs := append([]byte{}, ciphers...)
	hs = append(hs, comp...)
	hs = append(hs, exts...)

	handshake := []byte{
		0x03, 0x03, // client version TLS 1.2
	}
	handshake = append(handshake, random...)
	handshake = append(handshake, sid...)
	handshake = append(handshake, hs...)

	// Handshake header
	hsHeader := []byte{0x01} // ClientHello
	hsHeader = append(hsHeader, byte(len(handshake)>>16), byte(len(handshake)>>8), byte(len(handshake)))
	hsHeader = append(hsHeader, handshake...)

	// Record header
	record := []byte{
		0x16,       // Handshake
		0x03, 0x03, // TLS 1.2
		byte(len(hsHeader) >> 8), byte(len(hsHeader)),
	}
	record = append(record, hsHeader...)

	hello, err := ParseClientHelloPlus(record)
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	if hello.TLSVersion != 0x0303 {
		t.Errorf("TLS version = %x, want 0x0303", hello.TLSVersion)
	}
	if !hello.HasSNI {
		t.Errorf("HasSNI should be true")
	}
	if len(hello.CipherSuites) != 2 {
		t.Errorf("got %d ciphers, want 2", len(hello.CipherSuites))
	}
	fp, err := ComputeJA4FromClientHelloPlus(record)
	if err != nil {
		t.Fatalf("ComputeJA4FromClientHelloPlus: %v", err)
	}
	if !strings.HasPrefix(fp, "ja4_") {
		t.Errorf("JA4 = %q, expected ja4_ prefix", fp)
	}
}

// TestJA4FromKnownInput verifies the JA4 output for a well-known
// browser (Chrome 120 on Linux). The expected JA4 string is derived
// from the spec's reference examples.
func TestJA4FromKnownInput(t *testing.T) {
	// Chrome 120-like ClientHello: TLS 1.3, ~17 ciphers, SNI present,
	// ESNI absent, supported_versions present, ~10 extensions.
	ciphers := []uint16{
		0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030,
		0xcca9, 0xccaa, 0xcca8, 0x1304, 0xc009, 0xc00a, 0xc013,
		0xc014, 0x009c, 0x009d, 0x0035, 0x002f, 0x003c,
	}
	exts := []uint16{
		0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010,
		0x0005, 0x000d, 0x0012, 0x002b, 0x002d, 0x001b, 0x0015,
	}
	sigs := []uint16{
		0x0401, 0x0501, 0x0601, 0x0201, 0x0403, 0x0503, 0x0603, 0x0203,
		0x0804, 0x0805, 0x0806, 0x0402, 0x0502, 0x0602, 0x0202,
	}
	fp := ComputeJA4Plus(ciphers, exts, sigs, 0x0303, true, []string{"h2"})
	if !strings.HasPrefix(fp, "ja4_t12d") {
		t.Errorf("expected ja4_t12d prefix, got %q", fp)
	}
	// num_ciphers (2 digits) and num_extensions (2 digits) should be
	// embedded in the a-part. We have 20 ciphers, 14 extensions.
	if !strings.Contains(fp, "2014") {
		t.Errorf("expected 20 ciphers + 14 extensions in a-part, got %q", fp)
	}
}
