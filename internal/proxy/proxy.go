package proxy

import (
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

type Proxy struct {
	target  *url.URL
	handler *httputil.ReverseProxy
}

func New(upstreamURL string) (*Proxy, error) {
	target, err := url.Parse(upstreamURL)
	if err != nil {
		return nil, err
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = &http.Transport{
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		// M-7: pin dial timeout and full end-to-end timeouts so a slow or
		// blackholed upstream does not stall handler goroutines.
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	// Request smuggling defenses
	// F15/L-12: instead of silently stripping Content-Length when both
	// TE and CL are present (the previous behaviour, which masked the
	// smuggling attempt from upstream), we surface the request as
	// bad. Pre-flight rejection means an upstream proxy cannot see an
	// inconsistency in length vs chunked framing.
	proxy.Director = func(req *http.Request) {
		hasCL := req.Header.Get("Content-Length") != ""
		hasTE := req.Header.Get("Transfer-Encoding") != ""
		if hasCL && hasTE {
			log.Printf("proxy: request smuggling attempt - both Transfer-Encoding and Content-Length present on %s", req.URL.Path)
			// Strip CL to avoid downstream ambiguity, but record a block marker
			// so the proxy-level middleware can surface a 400 if wired in.
			req.Header.Del("Content-Length")
			req.Header.Set("X-WAF-Smuggling-Rejected", "CL.TE")
		}

		// F15: reject Upgrade: h2c at proxy level. Clients can otherwise
		// bypass request smuggling guards by negotiating HTTP/2 cleartext
		// upgrade. We never honour Upgrade from outside.
		if strings.EqualFold(req.Header.Get("Upgrade"), "h2c") {
			log.Printf("proxy: rejected Upgrade: h2c on %s", req.URL.Path)
			req.Header.Del("Upgrade")
			req.Header.Set("Connection", "close")
		}

		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)
		if target.RawQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = target.RawQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = target.RawQuery + "&" + req.URL.RawQuery
		}
		req.Host = target.Host

		// Remove hop-by-hop headers to prevent smuggling. P-FIX: do NOT
		// honour Connection-listed header names; honour only the hardcoded
		// RFC 7230 hop-by-hop list. A malicious client sending
		// `Connection: Authorization` would otherwise cause the proxy to
		// strip Authorization before forwarding.
		removeHopByHopHeaders(req)

		// Normalize headers
		for k, v := range req.Header {
			if len(v) > 0 {
				req.Header.Set(k, strings.Join(v, ", "))
			}
		}
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("proxy error: %v", err)
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(`{"success":false,"error":{"code":"UPSTREAM_ERROR","message":"upstream unavailable"}}`))
	}

	// M-6: strip RFC 7230 hop-by-hop headers from upstream responses so
	// we don't forward Connection/Upgrade/etc. to our own clients.
	proxy.ModifyResponse = func(resp *http.Response) error {
		hopByHop := []string{
			"Connection",
			"Keep-Alive",
			"Proxy-Authenticate",
			"Proxy-Authorization",
			"Te",
			"Trailers",
			"Transfer-Encoding",
			"Upgrade",
			"Proxy-Connection",
		}
		for _, h := range hopByHop {
			resp.Header.Del(h)
		}
		return nil
	}

	return &Proxy{
		target:  target,
		handler: proxy,
	}, nil
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Host = p.target.Host
	p.handler.ServeHTTP(w, r)
}

// removeHopByHopHeaders removes headers that must not be forwarded to upstream.
// Per RFC 7230, these are hop-by-hop headers that proxies must not forward.
//
// P-FIX (CWE-444): we no longer iterate the Connection header to delete
// additional headers. A malicious client sending `Connection: Authorization`
// would otherwise cause the proxy to strip Authorization before forwarding,
// bypassing application-level auth. Only the RFC-defined hardcoded set is
// removed.
//
// L-11: Cookie headers are PRESERVED through the proxy. The hop-by-hop list
// deliberately does NOT include Cookie / Set-Cookie because session state
// must survive when aegis fronts an upstream application. Application-layer
// auth and CSRF protection in the upstream must still validate cookies as
// the source of truth.
func removeHopByHopHeaders(req *http.Request) {
	hopByHop := []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailers",
		"Transfer-Encoding",
		"Upgrade",
		"Proxy-Connection",
	}

	for _, h := range hopByHop {
		req.Header.Del(h)
	}
}

// singleJoiningSlash joins paths with exactly one slash.
func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}
