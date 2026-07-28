package rules

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html"
	"net/url"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// Transform normalizes input before rule matching.
type Transform func(string) string

var transformRegistry = map[string]Transform{
	"urldecode":           urlDecode,
	"htmlentitydecode":    htmlEntityDecode,
	"base64decode":        base64Decode,
	"hexdecode":           hexDecode,
	// F27: `unicodeNormalize` now performs real NFKC normalization plus
	// full Unicode lower-casing. The `asciifoldlower` name only
	// lowercases non-ASCII letters, which we keep available as a
	// distinct cheap transform. Legacy configs using either name
	// continue to work.
	"asciifoldlower":      asciiFoldLower,
	"unicodenormalize":    unicodeNormalize,
	"jsdecode":            jsDecode,
	"cssdecode":           cssDecode,
	"collapsewhitespace":  collapseWhitespace,
	"removenulls":         removeNulls,
	"lowercase":           strings.ToLower,
}

// GetTransform returns a transform by name, or nil if not found.
func GetTransform(name string) Transform {
	return transformRegistry[strings.ToLower(strings.TrimSpace(name))]
}

// ApplyTransforms applies a list of transforms in order.
func ApplyTransforms(input string, transformNames []string) string {
	result := input
	for _, name := range transformNames {
		t := GetTransform(name)
		if t != nil {
			result = t(result)
		}
	}
	return result
}

// ParseTransformNames parses a comma-separated string of transform names.
func ParseTransformNames(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var names []string
	for _, p := range parts {
		trimmed := strings.ToLower(strings.TrimSpace(p))
		if trimmed != "" {
			names = append(names, trimmed)
		}
	}
	return names
}

func urlDecode(s string) string {
	decoded, err := url.QueryUnescape(s)
	if err != nil {
		return s
	}
	return decoded
}

func htmlEntityDecode(s string) string {
	return html.UnescapeString(s)
}

func base64Decode(s string) string {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		// Try without padding
		decoded, err = base64.RawStdEncoding.DecodeString(s)
		if err != nil {
			return s
		}
	}
	return string(decoded)
}

func hexDecode(s string) string {
	// Decode %XX sequences
	var result strings.Builder
	i := 0
	for i < len(s) {
		if i+2 < len(s) && s[i] == '%' {
			b, err := hex.DecodeString(s[i+1 : i+3])
			if err == nil {
				result.Write(b)
				i += 3
				continue
			}
		}
		result.WriteByte(s[i])
		i++
	}
	return result.String()
}

// F27: real Unicode normalization (NFKC) followed by case-folding.
// Defeats confusable-character bypasses like fullwidth SELECT,
// mathematical-bold "union select", and case-folding evasion via
// Cyrillic / Greek letters.
func unicodeNormalize(s string) string {
	n := norm.NFKC.String(s)
	var b strings.Builder
	b.Grow(len(n))
	for _, r := range n {
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}

// asciiFoldLower lowercases non-ASCII letters and leaves everything else
// unchanged. It does NOT perform Unicode normalization (NFKD/NFKC); use
// `unicodeNormalize` for that. Exposed separately as a cheap transform.
func asciiFoldLower(s string) string {
	var result strings.Builder
	for _, r := range s {
		if r > 127 {
			if unicode.IsLetter(r) {
				result.WriteRune(unicode.ToLower(r))
			} else {
				result.WriteRune(r)
			}
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

func jsDecode(s string) string {
	var result strings.Builder
	i := 0
	for i < len(s) {
		if i+1 < len(s) && s[i] == '\\' {
			switch s[i+1] {
			case 'n':
				result.WriteByte('\n')
				i += 2
			case 'r':
				result.WriteByte('\r')
				i += 2
			case 't':
				result.WriteByte('\t')
				i += 2
			case '\\':
				result.WriteByte('\\')
				i += 2
			case '\'':
				result.WriteByte('\'')
				i += 2
			case '"':
				result.WriteByte('"')
				i += 2
			case 'x':
				if i+3 < len(s) {
					b, err := hex.DecodeString(s[i+2 : i+4])
					if err == nil {
						result.Write(b)
						i += 4
						continue
					}
				}
				result.WriteByte(s[i])
				i++
			case 'u':
				if i+5 < len(s) {
					// P-FIX: \uXXXX — actually decode to UTF-8 bytes.
					// The previous code wrote the raw hex chars
					// (e.g. "00A0") to the output, which meant a
					// rule matching a non-breaking space (U+00A0)
					// would never match the redacted form.
					var u uint32
					_, err := fmt.Sscanf(s[i+2:i+6], "%x", &u)
					if err == nil {
						if u < 0x80 {
							result.WriteByte(byte(u))
						} else if u < 0x800 {
							result.WriteByte(0xC0 | byte(u>>6))
							result.WriteByte(0x80 | byte(u&0x3F))
						} else if u < 0x10000 {
							result.WriteByte(0xE0 | byte(u>>12))
							result.WriteByte(0x80 | byte((u>>6)&0x3F))
							result.WriteByte(0x80 | byte(u&0x3F))
						} else {
							result.WriteByte(0xF0 | byte(u>>18))
							result.WriteByte(0x80 | byte((u>>12)&0x3F))
							result.WriteByte(0x80 | byte((u>>6)&0x3F))
							result.WriteByte(0x80 | byte(u&0x3F))
						}
						i += 6
						continue
					}
				}
				result.WriteByte(s[i])
				i++
			default:
				result.WriteByte(s[i])
				i++
			}
		} else {
			result.WriteByte(s[i])
			i++
		}
	}
	return result.String()
}

func cssDecode(s string) string {
	var result strings.Builder
	i := 0
	for i < len(s) {
		if i+1 < len(s) && s[i] == '\\' {
			if s[i+1] == '\n' {
				// CSS line continuation
				i += 2
				continue
			}
			if i+2 < len(s) {
				b, err := hex.DecodeString(s[i+1 : i+3])
				if err == nil {
					result.Write(b)
					i += 3
					continue
				}
			}
			result.WriteByte(s[i+1])
			i += 2
		} else {
			result.WriteByte(s[i])
			i++
		}
	}
	return result.String()
}

func collapseWhitespace(s string) string {
	var result strings.Builder
	prevSpace := false
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			if !prevSpace {
				result.WriteByte(' ')
				prevSpace = true
			}
		} else {
			result.WriteRune(r)
			prevSpace = false
		}
	}
	return result.String()
}

func removeNulls(s string) string {
	return strings.ReplaceAll(s, "\x00", "")
}
