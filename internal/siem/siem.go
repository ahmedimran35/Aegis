package siem

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"log/syslog"
	"net"
	"os"
	"strings"
	"time"
)

// Config holds SIEM configuration.
type Config struct {
	Enabled     bool
	Type        string // syslog, file
	SyslogAddr  string
	FilePath    string
	Format      string // json, cef
	MinSeverity string
}

// Event represents a SIEM export event.
type Event struct {
	Timestamp   string      `json:"timestamp"`
	EventType   string      `json:"event_type"`
	ClientIP    string      `json:"client_ip"`
	Method      string      `json:"method"`
	Path        string      `json:"path"`
	Action      string      `json:"action"`
	RuleID      int         `json:"rule_id,omitempty"`
	ThreatScore float64     `json:"threat_score,omitempty"`
	UserAgent   string      `json:"user_agent,omitempty"`
	Country     string      `json:"country,omitempty"`
	Details     interface{} `json:"details,omitempty"`
}

// Exporter exports Aegis events to SIEM systems.
//
// P-FIX (M-53): the syslog transport defaults to tcp+tls in production.
// UDP is still accepted for legacy compatibility but emits a one-time
// warning at startup so operators notice the loss of confidentiality
// and integrity guarantees.
type Exporter struct {
	config    Config
	writer    *syslog.Writer
	tlsConn   net.Conn
	syslogBuf []byte // latest pending line to flush
	file      *os.File
	stopCh    chan struct{}
}

// NewExporter creates a SIEM exporter.
//
// Syslog transports are detected from the scheme prefix on
// cfg.SyslogAddr:
//   - "udp://host:514"     → UDP (legacy; warns at startup)
//   - "tcp://host:601"     → plain TCP
//   - "tls://host:6514"    → TCP over TLS (recommended)
//   - "tcptls://host:6514" → alias for tls://
//   - "host:514" (no scheme) → defaults to TCP+tls for safety
func NewExporter(cfg Config) *Exporter {
	if !cfg.Enabled {
		return &Exporter{config: cfg}
	}

	e := &Exporter{
		config: cfg,
		stopCh: make(chan struct{}),
	}

	switch cfg.Type {
	case "syslog":
		_, addr, scheme := parseSyslogTarget(cfg.SyslogAddr)
		if addr == "" {
			addr = cfg.SyslogAddr
		}
		switch scheme {
		case "udp":
			log.Printf("siem: WARNING using plaintext UDP syslog to %s — events are unauthenticated; switch to tls:// for production", cfg.SyslogAddr)
			w, err := syslog.Dial("udp", addr, syslog.LOG_INFO|syslog.LOG_LOCAL0, "aegis")
			if err != nil {
				log.Printf("siem: connect syslog: %v", err)
				e.config.Enabled = false
				return e
			}
			e.writer = w
			log.Printf("siem: connected to syslog (udp) at %s", addr)
		case "tcp":
			w, err := syslog.Dial("tcp", addr, syslog.LOG_INFO|syslog.LOG_LOCAL0, "aegis")
			if err != nil {
				log.Printf("siem: connect syslog: %v", err)
				e.config.Enabled = false
				return e
			}
			e.writer = w
			log.Printf("siem: connected to syslog (tcp) at %s", addr)
		default: // tls / tcptls / "" → tcp over TLS
			conn, err := tls.Dial("tcp", addr, &tls.Config{
				MinVersion: tls.VersionTLS12,
			})
			if err != nil {
				log.Printf("siem: connect syslog (tcp+tls) at %s: %v", addr, err)
				e.config.Enabled = false
				return e
			}
			e.tlsConn = conn
			log.Printf("siem: connected to syslog (tcp+tls) at %s", addr)
		}

	case "file":
		f, err := os.OpenFile(cfg.FilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			log.Printf("siem: open file: %v", err)
			e.config.Enabled = false
			return e
		}
		e.file = f
		log.Printf("siem: exporting to %s", cfg.FilePath)
	}

	return e
}

// parseSyslogTarget splits a syslog target string into (network, addr,
// scheme). If no scheme is supplied, scheme is empty so the caller can
// apply its own default.
func parseSyslogTarget(target string) (network, addr, scheme string) {
	if target == "" {
		return "", "", ""
	}
	if i := strings.Index(target, "://"); i > 0 {
		scheme = strings.ToLower(target[:i])
		target = target[i+3:]
	}
	addr = target
	switch scheme {
	case "udp":
		network = "udp"
	case "tcp":
		network = "tcp"
	case "tls", "tcptls":
		network = "tcp+tls"
	}
	return network, addr, scheme
}

// Export sends an event to the SIEM system.
func (e *Exporter) Export(event Event) {
	if !e.config.Enabled {
		return
	}

	event.Timestamp = time.Now().UTC().Format(time.RFC3339)

	var line string
	switch e.config.Format {
	case "cef":
		line = e.toCEF(event)
	default:
		data, _ := json.Marshal(event)
		line = string(data)
	}

	switch e.config.Type {
	case "syslog":
		switch {
		case e.writer != nil:
			e.writer.Info(line)
		case e.tlsConn != nil:
			// RFC 5424 minimal envelope (PRI=134 ≈ INFO). Using a
			// newline-delimited RFC 3164-style line keeps any syslog
			// receiver happy; \n is the canonical record separator.
			if _, err := fmt.Fprintf(e.tlsConn, "<134>1 %s aegis - - - %s\n",
				event.Timestamp, strings.TrimRight(line, "\n")); err != nil {
				log.Printf("siem: tls write: %v", err)
			}
		}
	case "file":
		if e.file != nil {
			if _, err := e.file.WriteString(line + "\n"); err != nil {
				log.Printf("siem: write: %v", err)
			}
		}
	}
}

func (e *Exporter) toCEF(event Event) string {
	severity := "3"
	if event.ThreatScore > 0.7 {
		severity = "7"
	} else if event.ThreatScore > 0.4 {
		severity = "5"
	}

	// Escape CEF delimiters in user-controlled fields
	return fmt.Sprintf("CEF:0|Aegis|Engine|1.0|%s|%s %s|%s|src=%s request=%s act=%s",
		escapeCEF(event.EventType), escapeCEF(event.Method), escapeCEF(event.Path), severity,
		escapeCEF(event.ClientIP), escapeCEF(event.Path), escapeCEF(event.Action))
}

// escapeCEF escapes special characters for CEF format.
func escapeCEF(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "|", `\|`)
	s = strings.ReplaceAll(s, "=", `\=`)
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}

// ExportAsync sends an event asynchronously. P-FIX (H-2): the spawned
// goroutine is wrapped in a recover() and respects e.stopCh so a
// panic in Export does not take down the process and a stopped
// exporter does not leak goroutines.
func (e *Exporter) ExportAsync(event Event) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("siem: ExportAsync panic recovered: %v", r)
			}
		}()
		select {
		case <-e.stopCh:
			return
		default:
		}
		e.Export(event)
	}()
}

// Stop closes the exporter.
func (e *Exporter) Stop() {
	if !e.config.Enabled {
		return
	}
	close(e.stopCh)
	if e.writer != nil {
		e.writer.Close()
	}
	if e.tlsConn != nil {
		_ = e.tlsConn.Close()
	}
	if e.file != nil {
		e.file.Close()
	}
}
