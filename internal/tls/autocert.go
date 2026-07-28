package tls

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// Manager handles automatic TLS certificate management via Let's Encrypt.
type Manager struct {
	manager    *autocert.Manager
	httpsAddr  string
	httpAddr   string
	domains    []string
}

// Config holds TLS configuration.
type Config struct {
	Domains    []string
	Email      string
	CacheDir   string
	HTTPSAddr  string
	HTTPAddr   string
}

// NewManager creates a TLS manager with Let's Encrypt autocert.
func NewManager(cfg Config) *Manager {
	m := &autocert.Manager{
		Cache:      autocert.DirCache(cfg.CacheDir),
		Prompt:     autocert.AcceptTOS,
		Email:      cfg.Email,
		HostPolicy: autocert.HostWhitelist(cfg.Domains...),
	}

	return &Manager{
		manager:   m,
		httpsAddr: cfg.HTTPSAddr,
		httpAddr:  cfg.HTTPAddr,
		domains:   cfg.Domains,
	}
}

// TLSConfig returns the TLS configuration for the server.
//
// P-FIX (M-40): explicit CurvePreferences enforces a deterministic
// ECDHE group selection (X25519 preferred, then P-256 as fallback). We
// also pin MinVersion to TLS 1.2 — TLS 1.0/1.1 are forbidden (CWE-326).
func (tm *Manager) TLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate:           tm.manager.GetCertificate,
		MinVersion:               tls.VersionTLS12,
		CipherSuites:             modernCipherSuites(),
		PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		},
	}
}

// modernCipherSuites returns the Mozilla "Modern" TLS 1.2 cipher suite list
// (ECDHE + AEAD only). TLS 1.3 cipher suites are not configurable via this
// list; Go's TLS 1.3 implementation selects from a fixed secure set.
func modernCipherSuites() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}
}

// HTTPHandler returns an HTTP handler that redirects to HTTPS and handles ACME challenges.
func (tm *Manager) HTTPHandler() http.Handler {
	return tm.manager.HTTPHandler(nil)
}

// StartServers starts both HTTP (ACME + redirect) and HTTPS servers.
func (tm *Manager) StartServers(handler http.Handler) (*http.Server, *http.Server) {
	// HTTPS server
	httpsServer := &http.Server{
		Addr:      tm.httpsAddr,
		Handler:   handler,
		TLSConfig: tm.TLSConfig(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// HTTP server (ACME challenges + redirect)
	httpServer := &http.Server{
		Addr:         tm.httpAddr,
		Handler:      tm.HTTPHandler(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	go func() {
		log.Printf("tls: HTTP server on %s (ACME + redirect)", tm.httpAddr)
		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
			log.Printf("tls: HTTP server error: %v", err)
		}
	}()

	go func() {
		log.Printf("tls: HTTPS server on %s (Let's Encrypt)", tm.httpsAddr)
		if err := httpsServer.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
			log.Printf("tls: HTTPS server error: %v", err)
		}
	}()

	log.Printf("tls: configured for domains %v", tm.domains)

	return httpServer, httpsServer
}

// Shutdown gracefully stops both servers.
func (tm *Manager) Shutdown(httpServer, httpsServer *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if httpServer != nil {
		httpServer.Shutdown(ctx)
	}
	if httpsServer != nil {
		httpsServer.Shutdown(ctx)
	}
}
