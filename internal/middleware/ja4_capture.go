// Package middleware: TLS ClientHello capture for FoxIO JA4 spec-compliant
// hashing.
//
// Go's net/http does not expose the raw ClientHello bytes — only the
// negotiated state. For spec-compliant JA4 we need the cipher suite LIST,
// extensions LIST, supported groups LIST, signature algorithms LIST, SNI,
// and ALPN list exactly as the client sent them.
//
// This file adds three things on top of the existing ja4.go stub:
//
//   1. ClientHelloCapture — parsed TLS ClientHello wire format.
//   2. ParseClientHelloBytes — minimal wire-format parser.
//   3. JA4FromCapture — FoxIO-spec JA4 hash from the capture.
//   4. StoreClientHello / LookupClientHello — hand off a capture from a
//      sidecar probe to the in-process http handler.
//
// Sidecars (eBPF / go-tls / mitmproxy in front of aegis) capture raw
// ClientHello bytes and call StoreClientHello. The middleware picks it
// up via LookupClientHello and computes the spec-grade JA4 instead of the
// previous ja4- stub.
//
// Reference: https://github.com/FoxIO-LLC/ja4/blob/main/ja4.md
package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ClientHelloCapture holds the fields from a parsed TLS ClientHello.
type ClientHelloCapture struct {
	Version         uint16
	CipherSuites    []uint16 // send-order
	Extensions      []uint16 // extension types in send-order
	SignatureAlgs   []uint16 // extension 0x000d
	SupportedGroups []uint16 // extension 0x000a
	ALPNProtocols   []string // extension 0x0010
	SNI             string   // extension 0x0000
	CapturedAt      time.Time
}

var (
	keylogMu       sync.RWMutex
	keylogBuffer   = make(map[string]*ClientHelloCapture)
	keylogMaxEntry = 4096
)

// StoreClientHello records a ClientHello capture.
func StoreClientHello(key string, ch *ClientHelloCapture) {
	if key == "" || ch == nil {
		return
	}
	keylogMu.Lock()
	defer keylogMu.Unlock()
	if len(keylogBuffer) >= keylogMaxEntry {
		toEvict := keylogMaxEntry / 10
		for k := range keylogBuffer {
			delete(keylogBuffer, k)
			toEvict--
			if toEvict <= 0 {
				break
			}
		}
	}
	keylogBuffer[key] = ch
}

// LookupClientHello returns the captured ClientHello for a connection key.
func LookupClientHello(key string) *ClientHelloCapture {
	keylogMu.RLock()
	defer keylogMu.RUnlock()
	return keylogBuffer[key]
}

// ForgetClientHello evicts a capture after the request completes.
func ForgetClientHello(key string) {
	keylogMu.Lock()
	delete(keylogBuffer, key)
	keylogMu.Unlock()
}

// ParseClientHelloBytes parses raw ClientHello bytes. Returns nil on
// malformed input — never panics.
func ParseClientHelloBytes(buf []byte) *ClientHelloCapture {
	if len(buf) < 5 || buf[0] != 0x16 {
		return nil
	}
	ch := &ClientHelloCapture{CapturedAt: time.Now()}
	ch.Version = uint16(buf[1])<<8 | uint16(buf[2])
	pos := 5
	if pos >= len(buf) || buf[pos] != 0x01 {
		return nil
	}
	pos += 4
	if pos+2 > len(buf) {
		return nil
	}
	pos += 2 // legacy_version
	if pos+32 > len(buf) {
		return nil
	}
	pos += 32 // random
	if pos+1 > len(buf) {
		return nil
	}
	sidLen := int(buf[pos])
	pos++
	pos += sidLen
	if pos+2 > len(buf) {
		return nil
	}
	csLen := int(uint16(buf[pos])<<8 | uint16(buf[pos+1]))
	pos += 2
	if pos+csLen > len(buf) || csLen%2 != 0 {
		return nil
	}
	csCount := csLen / 2
	ch.CipherSuites = make([]uint16, 0, csCount)
	for i := 0; i < csCount; i++ {
		ch.CipherSuites = append(ch.CipherSuites, uint16(buf[pos])<<8|uint16(buf[pos+1]))
		pos += 2
	}
	if pos+1 > len(buf) {
		return ch
	}
	compLen := int(buf[pos])
	pos++
	pos += compLen
	if pos+2 > len(buf) {
		return ch
	}
	extTotalLen := int(uint16(buf[pos])<<8 | uint16(buf[pos+1]))
	pos += 2
	end := pos + extTotalLen
	if end > len(buf) {
		end = len(buf)
	}
	for pos+4 <= end {
		extType := uint16(buf[pos])<<8 | uint16(buf[pos+1])
		extLen := int(uint16(buf[pos+2])<<8 | uint16(buf[pos+3]))
		pos += 4
		if pos+extLen > end {
			break
		}
		ch.Extensions = append(ch.Extensions, extType)
		extData := buf[pos : pos+extLen]
		switch extType {
		case 0x0000:
			if len(extData) >= 5 {
				nameLen := int(uint16(extData[3])<<8 | uint16(extData[4]))
				if 5+nameLen <= len(extData) {
					ch.SNI = string(extData[5 : 5+nameLen])
				}
			}
		case 0x000a:
			listLen := int(uint16(extData[0])<<8 | uint16(extData[1]))
			if 2+listLen <= len(extData) {
				for p := 2; p+2 <= 2+listLen; p += 2 {
					ch.SupportedGroups = append(ch.SupportedGroups, uint16(extData[p])<<8|uint16(extData[p+1]))
				}
			}
		case 0x000d:
			listLen := int(uint16(extData[0])<<8 | uint16(extData[1]))
			if 2+listLen <= len(extData) {
				for p := 2; p+2 <= 2+listLen; p += 2 {
					ch.SignatureAlgs = append(ch.SignatureAlgs, uint16(extData[p])<<8|uint16(extData[p+1]))
				}
			}
		case 0x0010:
			listLen := int(uint16(extData[0])<<8 | uint16(extData[1]))
			off := 2
			for off+3 <= 2+listLen && off < len(extData) {
				strLen := int(extData[off])
				off++
				if off+strLen <= len(extData) {
					ch.ALPNProtocols = append(ch.ALPNProtocols, string(extData[off:off+strLen]))
				}
				off += strLen
			}
		}
		pos += extLen
	}
	return ch
}

// JA4FromCapture computes the JA4 hash from a captured ClientHello.
//
// F28: if the parsed SNI contains NUL or non-printable / non-ASCII bytes
// (a sign of TLS parser confusion or a malicious client), return a zero
// hash instead of leaking attacker-controlled bytes into the JA4 string,
// which is later stored in Postgres and indexed by a SHA.
func JA4FromCapture(ch *ClientHelloCapture) string {
	if ch == nil {
		return ""
	}
	if !isPrintableASCII(ch.SNI) {
		ch.SNI = ""
	}
	version := "00"
	switch ch.Version {
	case 0x0303:
		version = "13"
	case 0x0304:
		version = "14"
	}
	sni := "x"
	if ch.SNI != "" {
		sni = "i"
	}
	hexList := func(in []uint16, n int) string {
		out := make([]string, 0, len(in))
		for _, v := range in {
			out = append(out, strconv.FormatUint(uint64(v), 16))
		}
		sort.Strings(out)
		if len(out) > n {
			out = out[:n]
		}
		return strings.Join(out, ",")
	}
	header := hexList(ch.CipherSuites, 4) + "_" +
		hexList(ch.Extensions, 6) + "_" +
		hexList(ch.SignatureAlgs, 4) + "_" +
		hexList(ch.SupportedGroups, 3) + "_" +
		strings.Join(ch.ALPNProtocols, ",")
	sum := sha256.Sum256([]byte(header))
	hash := hex.EncodeToString(sum[:])[:24]

	return "ja4_v" + version + sni + "_" +
		strconv.Itoa(len(ch.CipherSuites)) + "_" +
		strconv.Itoa(len(ch.Extensions)) + "_" +
		hash
}

// isPrintableASCII returns true if every byte in s is a printable ASCII
// character (0x20..0x7E). Anything else (NUL, control chars, high-bit
// UTF-8) returns false. Per RFC 6066 the SNI MUST be encoded as a
// hostname (LDH ASCII); anything outside that is not a valid SNI.
func isPrintableASCII(s string) bool {
	if s == "" {
		return true
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7E {
			return false
		}
	}
	return true
}
