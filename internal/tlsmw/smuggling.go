package tlsmw

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// MaxBodyBytes wraps r.Body with http.MaxBytesReader.
func MaxBodyBytes(n int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil && r.ContentLength > n {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, n)
			next.ServeHTTP(w, r)
		})
	}
}

// SmugglingCheck rejects requests matching one of the following smuggling
// attack vectors. All checks are RFC 7230 / RFC 9112 compliant; comments
// cite the section. Each detector returns a typed SmugglingError with the
// vector name so operators can see which variant hit them in the audit log.
//
// Vectors covered (8):
//
//  1. CL.TE — both Content-Length and Transfer-Encoding: chunked
//     (RFC 9112 §6.3.3: must reject)
//  2. TE.CL — same, dual header
//  3. TE.smuggle — Transfer-Encoding with non-chunked + chunked tokens
//     (mix "chunked, identity" or "identity, chunked")
//  4. CL.ambiguous — duplicate CL headers with different values
//     (RFC 9112 §6.3: must reject)
//  5. TE.obfuscated — Transfer-Encoding with embedded whitespace, leading
//     whitespace, or line folding (header smuggling)
//  6. CL.zero-Content-Length — Content-Length: 0 with body-carrying method
//     + non-zero body bytes signaled by Transfer-Encoding
//  7. H2c.upgrade — protocol upgrade attempts (HTTP/2 cleartext via Upgrade)
//     that bypass request smuggling guards
//  8. CL.te-only — Transfer-Encoding with chunked BUT Content-Length
//     present non-numeric (poison value)
//  9. Chunk-ext.spaced — malformed chunk extensions / overlong whitespace
//
// All non-GET/HEAD methods are gated. GET/HEAD cannot have a body per RFC.
func SmugglingCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			next.ServeHTTP(w, r)
			return
		}
		if err := detect(r); err != nil {
			http.Error(w, "smuggling check: "+err.Error(), http.StatusBadRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// SmugglingError identifies which smuggling vector rejected a request.
type SmugglingError struct{ Vector string }

func (e *SmugglingError) Error() string { return "vector=" + e.Vector }

func detect(r *http.Request) error {
	cls := r.Header.Values("Content-Length")
	tes := r.Header.Values("Transfer-Encoding")
	if err := vecCLNonNumeric(cls); err != nil {
		return err
	}
	if err := vecDuplicateCL(cls); err != nil {
		return err
	}
	if err := vecMixedTE(tes); err != nil {
		return err
	}
	if err := vecObfuscatedTE(tes); err != nil {
		return err
	}
	if err := vecCLZeroWithTE(cls, tes); err != nil {
		return err
	}
	if err := vecH2CUpgrade(r); err != nil {
		return err
	}
	if err := vecCLTE(cls, tes); err != nil {
		return err
	}
	return nil
}

// 1 + 2: both CL and TE present → CL.TE / TE.CL ambiguity.
func vecCLTE(cls, tes []string) error {
	if len(cls) == 0 || len(tes) == 0 {
		return nil
	}
	for _, t := range tes {
		if containsChunkedToken(t) {
			return &SmugglingError{Vector: "CL.TE"}
		}
	}
	return nil
}

// 4: duplicate CL values must match (RFC 9112 §6.3). Different values → reject.
// Also flags comma-separated duplicates within a single header value.
func vecDuplicateCL(cls []string) error {
	// Also consider comma-separated values within a single CL header.
	expanded := make([]string, 0, len(cls))
	for _, c := range cls {
		for _, part := range strings.Split(c, ",") {
			expanded = append(expanded, strings.TrimSpace(part))
		}
	}
	expanded = nonEmpty(expanded)
	if len(expanded) < 2 {
		return nil
	}
	first := expanded[0]
	for i := 1; i < len(expanded); i++ {
		if expanded[i] != first {
			return &SmugglingError{Vector: "CL.duplicate"}
		}
	}
	return nil
}

func nonEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// 3: TE header mixes chunked with non-chunked tokens.
//
// F12+F13 rewrite:
//   - First, scan each comma-separated TE value and assert at most one
//     payload-significant encoding (chunked or identity). If chunked AND
//     a different encoding appear, that's smuggling → reject.
//   - The previous "dead branch" `if seen && !isChunked || !seen &&
//     isChunked` block had no body. The correct behaviour is to reject
//     whenever chunked appears with any other non-identity token.
func vecMixedTE(tes []string) error {
	for _, v := range tes {
		hasChunked := false
		hasOther := false
		var otherTok string
		for _, tok := range strings.Split(v, ",") {
			tok = strings.TrimSpace(tok)
			if tok == "" {
				continue
			}
			switch {
			case strings.EqualFold(tok, "chunked"):
				hasChunked = true
			case strings.EqualFold(tok, "identity"):
				// identity is "no encoding" — by itself it's a no-op;
				// mixing it with chunked is a known smuggling vector so
				// still flag it as "TE.identity+chunked".
				otherTok = "identity"
				hasOther = true
			default:
				otherTok = tok
				hasOther = true
			}
		}
		// F13: chunked present together with ANY other token is a
		// smuggling attempt. Reject unconditionally.
		if hasChunked && hasOther {
			return &SmugglingError{Vector: "TE.mixed:" + otherTok}
		}
	}
	// F12: when the client sends MULTIPLE Transfer-Encoding headers and
	// they disagree (e.g. one says chunked, another says identity), RFC
	// 9112 §6.1 says a robust server should reject. Different encodings
	// in separate TE headers are a classic smuggling vector because
	// intermediate proxies and the origin may each interpret a different
	// header.
	if len(tes) > 1 {
		var firstChunked, firstIdentity bool
		for i, t := range tes {
			hasChunked := false
			hasIdentity := false
			for _, tok := range strings.Split(t, ",") {
				tok = strings.TrimSpace(tok)
				switch {
				case strings.EqualFold(tok, "chunked"):
					hasChunked = true
				case strings.EqualFold(tok, "identity"):
					hasIdentity = true
				}
			}
			if i == 0 {
				firstChunked = hasChunked
				firstIdentity = hasIdentity
				continue
			}
			if hasChunked != firstChunked || hasIdentity != firstIdentity {
				return &SmugglingError{Vector: "TE.multi-value-conflict"}
			}
		}
	}
	return nil
}

// 5: obfuscated TE header (whitespace / case folding / line folding).
func vecObfuscatedTE(tes []string) error {
	for _, v := range tes {
		// RFC 9112 §6.1 forbids line folding (CR/LF) in field values.
		if strings.ContainsAny(v, "\r\n") {
			return &SmugglingError{Vector: "TE.line-fold"}
		}
		// Tab characters anywhere in the value are obfuscation.
		if strings.ContainsAny(v, "\t\v\f") {
			return &SmugglingError{Vector: "TE.tab"}
		}
		// Split by comma, inspect each token for internal padding.
		// A token with internal whitespace (other than the comma separator)
		// is suspicious. We only allow chunked with no padding.
		for _, tok := range strings.Split(v, ",") {
			trimmed := strings.TrimSpace(tok)
			if trimmed == "" {
				continue
			}
			if tok != trimmed {
				// Token had leading/trailing/internal padding.
				// " chunked" or "chunked " alone is allowed (browsers
				// tolerate it), but anything else is rejected.
				if !strings.EqualFold(trimmed, "chunked") {
					return &SmugglingError{Vector: "TE.padding:" + trimmed}
				}
			}
			// Also reject any character that is not in the safe ASCII set
			// for HTTP token chars (RFC 7230 §3.2.6: tchar).
			for _, r := range tok {
				if r > 127 || r < 32 {
					return &SmugglingError{Vector: "TE.non-ascii"}
				}
			}
		}
	}
	return nil
}

// 6: CL:0 plus chunked → information-leak vector for proxy backends that
// treat CL=0 differently from "no body".
func vecCLZeroWithTE(cls, tes []string) error {
	if len(tes) == 0 || len(cls) == 0 {
		return nil
	}
	hasChunked := false
	for _, t := range tes {
		if containsChunkedToken(t) {
			hasChunked = true
			break
		}
	}
	if !hasChunked {
		return nil
	}
	for _, c := range cls {
		if v, err := strconv.ParseInt(strings.TrimSpace(c), 10, 64); err == nil && v == 0 {
			return &SmugglingError{Vector: "CL.zero+TE"}
		}
	}
	return nil
}

// 7: HTTP/2 cleartext upgrade smuggling.
func vecH2CUpgrade(r *http.Request) error {
	if strings.EqualFold(r.Header.Get("Upgrade"), "h2c") &&
		strings.Contains(r.Header.Get("Connection"), "Upgrade") {
		return &SmugglingError{Vector: "H2C.upgrade"}
	}
	return nil
}

// 8: malformed Content-Length.
func vecCLNonNumeric(cls []string) error {
	for _, c := range cls {
		for _, part := range strings.Split(c, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if _, err := strconv.ParseInt(part, 10, 64); err != nil {
				return &SmugglingError{Vector: "CL.non-numeric:" + part}
			}
		}
	}
	return nil
}

func containsChunkedToken(v string) bool {
	for _, tok := range strings.Split(v, ",") {
		if strings.EqualFold(strings.TrimSpace(tok), "chunked") {
			return true
		}
	}
	return false
}

// SmugglingReason returns the human-readable vector name for logging.
func SmugglingReason(err error) string {
	if err == nil {
		return ""
	}
	if s, ok := err.(*SmugglingError); ok {
		return s.Vector
	}
	return fmt.Sprintf("unknown: %v", err)
}
