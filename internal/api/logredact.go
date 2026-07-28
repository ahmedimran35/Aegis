package api

import (
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"

	chimw "github.com/go-chi/chi/v5/middleware"
)

// redactingLogger returns an HTTP middleware that logs each request after
// stripping sensitive query parameters (password, token, api_key, etc.).
// The default chi/v5 middleware renders the raw query string into logs,
// which can exfiltrate credentials if an attacker tricks an admin into
// clicking a crafted URL.
//
// M-16: replaces chimw.Logger with a redaction-aware version.
func redactingLogger() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ww := chimw.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r)

			q := redactQuery(r.URL.RawQuery)
			path := r.URL.Path
			if q != "" {
				path = path + "?" + q
			}
			ua := stripCtrl(r.Header.Get("User-Agent"))
			log.Printf("%s %s %d %dB ua=%q from=%s",
				r.Method, path, ww.Status(), ww.BytesWritten(), ua,
				stripCtrl(clientIPString(r)))
		})
	}
}

// redactQuery replaces the value of known-sensitive keys with "<redacted>".
func redactQuery(raw string) string {
	if raw == "" {
		return ""
	}
	vals, err := url.ParseQuery(raw)
	if err != nil {
		return "<unparseable>"
	}
	sensitive := map[string]bool{
		"password": true, "passwd": true, "pass": true,
		"token": true, "access_token": true, "refresh_token": true,
		"api_key": true, "apikey": true, "secret": true,
		"authorization": true, "auth": true,
	}
	for k := range vals {
		if sensitive[strings.ToLower(k)] {
			vals[k] = []string{"<redacted>"}
		}
	}
	return vals.Encode()
}

func clientIPString(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// stripCtrl removes control characters that could be used for log
// injection (e.g. \n, \r) before the value is appended to a log line.
func stripCtrl(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\t' {
			return -1
		}
		if r == 0x7f {
			return -1
		}
		return r
	}, s)
}
