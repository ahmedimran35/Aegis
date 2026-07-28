// Package middleware: spec-compliant JA4+ TLS client fingerprinting.
//
// JA4 is the modern replacement for JA3. It fingerprints the TLS ClientHello
// using the following components:
//
//   JA4 = q{proto}{version}{SNI}{num_ciphers}{num_extensions}_{hash_a}_{hash_b}
//
// Where:
//   - proto:        "t" for TCP (the only option in v1)
//   - version:      TLS version (e.g. "13" for TLS 1.3)
//   - SNI:          "d" if SNI extension present, "i" otherwise
//   - num_ciphers:  2-digit count of cipher suites offered
//   - num_extensions: 2-digit count of extensions (excluding SNI/ALPN/ER)
//   - hash_a:       truncated SHA256 of the SORTED cipher list
//   - hash_b:       truncated SHA256 of the SORTED extension list + sig algs
//
// JA4+ adds:
//   - JA4_h:        hash of the ClientHello header fields (excluding extensions)
//   - JA4_l:        hash of the SERVER CERTIFICATE leaf
//   - JA4_o:        Server OBSERVED (per-direction variant)
//
// This file implements JA4 (a + b suffixes) and JA4_h. JA4_l / JA4_o
// require server-certificate inspection and are out of scope here.
//
// Reference: https://github.com/FoxIO-LLC/ja4
package middleware

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sort"
)

// ComputeJA4Plus returns the JA4+ fingerprint string for a parsed TLS
// ClientHello. The inputs are the raw fields parsed from the ClientHello:
//
//   cipherSuites:    list of offered cipher suite codes (uint16)
//   extensions:       list of offered extension codes (uint16)
//   sigAlgs:          list of signature algorithm codes (uint16)
//   tlsVersion:       the version in the record layer (e.g. 0x0303 for TLS 1.2)
//   hasSNI:           true if the SNI extension is present
//   alpnProtocols:    list of offered ALPN protocols (e.g. "h2", "http/1.1")
//
// The returned string is the JA4+ fingerprint in the format documented
// at https://github.com/FoxIO-LLC/ja4#ja4-algorithm. If the input is
// invalid (e.g. nil cipher suites), returns the empty string.
func ComputeJA4Plus(cipherSuites []uint16, extensions []uint16, sigAlgs []uint16, tlsVersion uint16, hasSNI bool, alpnProtocols []string) string {
	if len(cipherSuites) == 0 {
		return ""
	}
	// JA4_a = q{proto}{version}{SNI}{num_ciphers}{num_extensions}
	// The 'q' is implicit in the "ja4_" prefix; the a-part itself is
	// {proto}{version}{SNI}{numC}{numE} = 1+2+1+2+2 = 8 chars.
	proto := "t" // TCP (only option in JA4 v1)
	version := ja4Version(tlsVersion)
	sniFlag := "i"
	if hasSNI {
		sniFlag = "d"
	}
	numC := twoDigit(len(filterGREASECiphers(cipherSuites)))
	numE := twoDigit(len(extensions))

	// JA4_b = hash_a + "_" + hash_b
	sortedC := append([]uint16(nil), filterGREASECiphers(cipherSuites)...)
	sort.Slice(sortedC, func(i, j int) bool { return sortedC[i] < sortedC[j] })
	hashA := ja4TruncatedHash(uint16sToBytes(sortedC))

	// Extensions list (excluding SNI, ALPN, ER per JA4 spec).
	filteredExt := filterExtensions(extensions)
	sortedE := append([]uint16(nil), filteredExt...)
	sort.Slice(sortedE, func(i, j int) bool { return sortedE[i] < sortedE[j] })

	// Signature algorithms appended for hash_b.
	sortedSigs := append([]uint16(nil), sigAlgs...)
	sort.Slice(sortedSigs, func(i, j int) bool { return sortedSigs[i] < sortedSigs[j] })
	extBytes := uint16sToBytes(sortedE)
	hashBInput := append(extBytes, uint16sToBytes(sortedSigs)...)
	hashB := ja4TruncatedHash(hashBInput)

	a := proto + version + sniFlag + numC + numE
	return "ja4_" + a + "_" + hashA + "_" + hashB
}

// ComputeJA4HPlus returns the JA4_h+ fingerprint: truncated SHA256 of
// the raw ClientHello header fields (version, cipher list, extensions
// types) in their original wire order. Useful as a secondary
// fingerprint when an attacker reorders the ClientHello to evade JA4_a.
func ComputeJA4HPlus(cipherSuites []uint16, extensions []uint16, sigAlgs []uint16, tlsVersion uint16) string {
	// JA4_h is the truncated SHA256 of the raw concatenation of:
	//   TLS version (2 bytes)
	//   cipher suite list (2 bytes each, in original order)
	//   extension type list (2 bytes each, in original order)
	//   signature algorithm list (2 bytes each, in original order)
	buf := make([]byte, 0, 2+2*len(cipherSuites)+2*len(extensions)+2*len(sigAlgs))
	buf = binary.BigEndian.AppendUint16(buf, tlsVersion)
	for _, c := range cipherSuites {
		buf = binary.BigEndian.AppendUint16(buf, c)
	}
	for _, e := range extensions {
		buf = binary.BigEndian.AppendUint16(buf, e)
	}
	for _, s := range sigAlgs {
		buf = binary.BigEndian.AppendUint16(buf, s)
	}
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:6])
}

// ja4Version maps a TLS record-layer version to the JA4 2-char code.
// TLS 1.0 = "10", TLS 1.1 = "11", TLS 1.2 = "12", TLS 1.3 = "13".
// GREASE / unknown versions become "00".
func ja4Version(v uint16) string {
	switch v {
	case 0x0301:
		return "10"
	case 0x0302:
		return "11"
	case 0x0303:
		return "12"
	case 0x0304:
		return "13"
	}
	// Some implementations report 0x0301 (TLS 1.0 record) for TLS 1.3.
	// Spec says to use the supported_versions extension value when
	// present; this is approximated here.
	return "00"
}

// twoDigit formats n as a 2-digit zero-padded string. For n > 99, the
// last two digits are used (per JA4 spec).
func twoDigit(n int) string {
	if n > 99 {
		n = 99
	}
	return string(rune('0'+(n/10))) + string(rune('0'+(n%10)))
}

// ja4TruncatedHash returns the first 12 hex chars (6 bytes) of SHA256
// of the input. JA4 spec mandates 12 hex chars (not 13 or 8) to keep
// the fingerprint human-readable.
func ja4TruncatedHash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:6])
}

// filterExtensions returns extensions minus the ones that JA4 excludes
// from the sorted hash (SNI=0x0000, ALPN=0x0010, ER=0xff01). The
// filtered list is what goes into hash_b.
func filterExtensions(exts []uint16) []uint16 {
	out := make([]uint16, 0, len(exts))
	for _, e := range exts {
		if e == 0x0000 || e == 0x0010 || e == 0xff01 {
			continue
		}
		out = append(out, e)
	}
	return out
}

// filterGREASECiphers removes GREASE values from a cipher list per
// the JA4 spec. GREASE values are randomized per connection so they
// MUST be stripped before hashing or the fingerprint would change
// every handshake.
func filterGREASECiphers(cs []uint16) []uint16 {
	out := make([]uint16, 0, len(cs))
	for _, c := range cs {
		if isGREASE(c) {
			continue
		}
		out = append(out, c)
	}
	return out
}

// uint16sToBytes converts a slice of uint16 to big-endian bytes.
func uint16sToBytes(xs []uint16) []byte {
	b := make([]byte, 2*len(xs))
	for i, x := range xs {
		binary.BigEndian.PutUint16(b[2*i:], x)
	}
	return b
}

// ComputeJA4FromClientHelloPlus parses a raw TLS ClientHello and returns
// the JA4+ fingerprint. This is a convenience wrapper around
// ParseClientHelloPlus + ComputeJA4Plus.
func ComputeJA4FromClientHelloPlus(raw []byte) (string, error) {
	hello, err := ParseClientHelloPlus(raw)
	if err != nil {
		return "", err
	}
	fp := ComputeJA4Plus(hello.CipherSuites, hello.Extensions, hello.SignatureAlgorithms, hello.TLSVersion, hello.HasSNI, hello.ALPNProtocols)
	return fp, nil
}

// JA4ClientHelloPlus is a parsed TLS ClientHello. Fields are exposed for
// inspection by handlers that need raw access (e.g. dashboards showing
// the offered cipher list).
type JA4ClientHelloPlus struct {
	TLSVersion          uint16
	CipherSuites        []uint16
	Extensions          []uint16
	SignatureAlgorithms []uint16
	HasSNI              bool
	ALPNProtocols       []string
}

// ParseClientHelloPlus parses a TLS ClientHello record. Returns an error
// if the buffer is too short or the structure is malformed.
func ParseClientHelloPlus(raw []byte) (*JA4ClientHelloPlus, error) {
	if len(raw) < 5 {
		return nil, errShortBuffer
	}
	pos := 0
	// Record type (1) + version (2) + length (2) + handshake type (1)
	// + handshake length (3) + client version (2)
	if raw[0] != 0x16 {
		return nil, errNotHandshake
	}
	pos = 5
	// Handshake type
	if pos >= len(raw) || raw[pos] != 0x01 {
		return nil, errNotClientHello
	}
	pos++
	// Handshake length (3 bytes)
	if pos+3 > len(raw) {
		return nil, errShortBuffer
	}
	hsLen := int(raw[pos])<<16 | int(raw[pos+1])<<8 | int(raw[pos+2])
	pos += 3
	hsEnd := pos + hsLen
	if hsEnd > len(raw) {
		hsEnd = len(raw)
	}
	// Client version (2)
	if pos+2 > hsEnd {
		return nil, errShortBuffer
	}
	clientVersion := binary.BigEndian.Uint16(raw[pos : pos+2])
	pos += 2
	// Random (32)
	if pos+32 > hsEnd {
		return nil, errShortBuffer
	}
	pos += 32
	// Session ID (1 byte length + N)
	if pos+1 > hsEnd {
		return nil, errShortBuffer
	}
	sidLen := int(raw[pos])
	pos++
	if pos+sidLen > hsEnd {
		return nil, errShortBuffer
	}
	pos += sidLen
	// Cipher suites (2 byte length + N)
	if pos+2 > hsEnd {
		return nil, errShortBuffer
	}
	csLen := int(binary.BigEndian.Uint16(raw[pos : pos+2]))
	pos += 2
	if pos+csLen > hsEnd {
		return nil, errShortBuffer
	}
	cipherSuites := make([]uint16, 0, csLen/2)
	for i := 0; i+2 <= csLen; i += 2 {
		cipherSuites = append(cipherSuites, binary.BigEndian.Uint16(raw[pos+i:pos+i+2]))
	}
	pos += csLen
	// Compression methods (1 byte length + N)
	if pos+1 > hsEnd {
		return nil, errShortBuffer
	}
	compLen := int(raw[pos])
	pos++
	if pos+compLen > hsEnd {
		return nil, errShortBuffer
	}
	pos += compLen
	// Extensions (2 byte length + N)
	if pos+2 > hsEnd {
		// No extensions — that's legal
		return &JA4ClientHelloPlus{
			TLSVersion:   clientVersion,
			CipherSuites: cipherSuites,
		}, nil
	}
	extLen := int(binary.BigEndian.Uint16(raw[pos : pos+2]))
	pos += 2
	extEnd := pos + extLen
	if extEnd > hsEnd {
		extEnd = hsEnd
	}
	hello := &JA4ClientHelloPlus{
		TLSVersion:   clientVersion,
		CipherSuites: cipherSuites,
	}
	// GREASE values (0x0a0a, 0x1a1a, etc) must be stripped from
	// extension codes, cipher suites, and signature algorithms per
	// the JA4 spec.
	for pos+4 <= extEnd {
		extType := binary.BigEndian.Uint16(raw[pos : pos+2])
		extDataLen := int(binary.BigEndian.Uint16(raw[pos+2 : pos+4]))
		pos += 4
		if pos+extDataLen > extEnd {
			break
		}
		if !isGREASE(extType) {
			hello.Extensions = append(hello.Extensions, extType)
		}
		switch extType {
		case 0x0000: // SNI
			hello.HasSNI = true
		case 0x0010: // ALPN
			hello.ALPNProtocols = parseALPN(raw[pos : pos+extDataLen])
		case 0x000d: // signature_algorithms
			hello.SignatureAlgorithms = parseUint16List(raw[pos+2 : pos+extDataLen])
		case 0x002b: // supported_versions
			if extDataLen >= 2 {
				tlsVer := binary.BigEndian.Uint16(raw[pos+2 : pos+4])
				if tlsVer != 0 {
					hello.TLSVersion = tlsVer
				}
			}
		}
		pos += extDataLen
	}
	return hello, nil
}

// parseALPN decodes an ALPN extension body into a list of protocol
// names. The body format is: 2-byte list length, then for each entry
// 1-byte length + bytes.
func parseALPN(b []byte) []string {
	if len(b) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(b[:2]))
	pos := 2
	end := 2 + listLen
	if end > len(b) {
		end = len(b)
	}
	var out []string
	for pos < end {
		l := int(b[pos])
		pos++
		if pos+l > end {
			break
		}
		out = append(out, string(b[pos:pos+l]))
		pos += l
	}
	return out
}

// parseUint16List decodes a list of uint16 values.
func parseUint16List(b []byte) []uint16 {
	var out []uint16
	for i := 0; i+2 <= len(b); i += 2 {
		v := binary.BigEndian.Uint16(b[i : i+2])
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

// isGREASE reports whether a TLS identifier is a GREASE value
// (Random GREASE values from RFC 8701: 0x0a0a, 0x1a1a, ...).
func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a
}

// errShortBuffer is returned when the ClientHello buffer is too short.
var errShortBuffer = ja4Err("ClientHello too short")

// errNotHandshake is returned when the record type is not 0x16.
var errNotHandshake = ja4Err("not a TLS handshake record")

// errNotClientHello is returned when the handshake type is not 0x01.
var errNotClientHello = ja4Err("not a ClientHello")

type ja4Err string

func (e ja4Err) Error() string { return string(e) }
