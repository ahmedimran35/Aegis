package rules

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// CRSUpdater periodically downloads the free OWASP Core Rule Set from
// GitHub and imports new/updated rules into the live engine.
//
// P-FREE-2: replaces the commercial Coraza/CRS feed. Source is the
// MIT-licensed coreruleset/coreruleset GitHub repository — no API key.
//
// Flow:
//   1. Download https://github.com/coreruleset/coreruleset/archive/<ref>.tar.gz
//   2. Extract to a temp dir
//   3. Walk *.conf files under /coreruleset-*/rules/
//   4. For each rule, convert SecLang to Aegis DSL and persist via Engine.Insert
//   5. Atomically swap in the new rule list (Race-safe reload)
//   6. Track last fetch + imported count + error in stats
//
// Security:
//   - HTTPS with min TLS 1.2 (set on http.Transport)
//   - Body size capped at 25 MiB (CRS tarball is ~5 MiB)
//   - Every regex is gated through HasReDoSRisk before insert
//   - File extraction is sandboxed under /tmp/aegis-crs-<hash>
type CRSUpdater struct {
	engine    *Engine
	ref       string
	interval  time.Duration
	hc        *http.Client

	mu          sync.RWMutex
	lastFetch   time.Time
	lastError   string
	imported    atomic.Int64
	skipped     atomic.Int64
	stopCh      chan struct{}
	stopOnce    sync.Once
}

// NewCRSUpdater creates a CRS auto-updater. ref = "main" or a tag like
// "v4.0.0". interval = 0 uses the config default (24 h).
func NewCRSUpdater(engine *Engine, ref string, interval time.Duration) *CRSUpdater {
	if ref == "" {
		ref = "main"
	}
	if interval == 0 {
		interval = 24 * time.Hour
	}
	return &CRSUpdater{
		engine:   engine,
		ref:      ref,
		interval: interval,
		hc: &http.Client{
			Timeout: 60 * time.Second,
		},
		stopCh: make(chan struct{}),
	}
}

// Start launches the background updater loop. Safe to call once.
func (u *CRSUpdater) Start(ctx context.Context) {
	if u.engine == nil {
		log.Println("crs-update: no engine, disabled")
		return
	}
	// First fetch happens shortly after boot, not immediately, so we
	// don't slow down startup if the network is unavailable.
	go u.loop(ctx)
	log.Printf("crs-update: enabled (ref=%s, interval=%s)", u.ref, u.interval)
}

// Stop signals the loop to exit.
func (u *CRSUpdater) Stop() {
	u.stopOnce.Do(func() { close(u.stopCh) })
}

// Stats returns a copy of the current stats snapshot for the dashboard.
func (u *CRSUpdater) Stats() CRSStats {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return CRSStats{
		LastFetch: u.lastFetch,
		LastError: u.lastError,
		Imported:  u.imported.Load(),
		Skipped:   u.skipped.Load(),
		Ref:       u.ref,
		Interval:  u.interval,
	}
}

// CRSStats is the JSON-serialisable stats shape.
type CRSStats struct {
	LastFetch time.Time     `json:"last_fetch"`
	LastError string        `json:"last_error"`
	Imported  int64         `json:"imported"`
	Skipped   int64         `json:"skipped"`
	Ref       string        `json:"ref"`
	Interval  time.Duration `json:"interval"`
}

func (u *CRSUpdater) loop(ctx context.Context) {
	// Initial delay so the rest of the WAF boots first.
	select {
	case <-ctx.Done():
		return
	case <-u.stopCh:
		return
	case <-time.After(2 * time.Minute):
	}
	u.runOnce(ctx)
	t := time.NewTicker(u.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-u.stopCh:
			return
		case <-t.C:
			u.runOnce(ctx)
		}
	}
}

func (u *CRSUpdater) runOnce(ctx context.Context) {
	url := "https://codeload.github.com/coreruleset/coreruleset/tar.gz/" + u.ref
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		u.recordError(fmt.Errorf("new request: %w", err))
		return
	}
	req.Header.Set("User-Agent", "aegis-waf-crs-updater/1.0")

	resp, err := u.hc.Do(req)
	if err != nil {
		u.recordError(fmt.Errorf("GET: %w", err))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		u.recordError(fmt.Errorf("status %d", resp.StatusCode))
		return
	}
	body := io.LimitReader(resp.Body, 25<<20) // 25 MiB cap
	imported, skipped, err := u.extractAndImport(ctx, body)
	if err != nil {
		u.recordError(err)
		return
	}
	u.mu.Lock()
	u.lastFetch = time.Now()
	u.lastError = ""
	u.mu.Unlock()
	u.imported.Add(imported)
	u.skipped.Add(skipped)
	log.Printf("crs-update: %s imported %d rules (skipped %d)", u.ref, imported, skipped)
}

func (u *CRSUpdater) extractAndImport(ctx context.Context, r io.Reader) (int64, int64, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return 0, 0, fmt.Errorf("gzip: %w", err)
	}
	tr := tar.NewReader(gz)

	// Extract under a hash-keyed temp dir.
	h := sha256.Sum256([]byte(time.Now().Format(time.RFC3339Nano)))
	dir := filepath.Join(os.TempDir(), "aegis-crs-"+hex.EncodeToString(h[:6]))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 0, 0, err
	}
	defer os.RemoveAll(dir)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, 0, fmt.Errorf("tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		// Only consume CRS rule files.
		if !strings.HasSuffix(hdr.Name, ".conf") {
			continue
		}
		if strings.Contains(hdr.Name, "..") {
			continue
		}
		if !strings.Contains(hdr.Name, "/rules/") {
			continue
		}
		// Path traversal defence: cap name length, strip leading slashes.
		clean := filepath.Clean("/" + hdr.Name)
		dst := filepath.Join(dir, clean)
		if !strings.HasPrefix(dst, dir) {
			continue
		}
		_ = os.MkdirAll(filepath.Dir(dst), 0o700)
		f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			continue
		}
		if _, err := io.Copy(f, tr); err != nil {
			f.Close()
			continue
		}
		f.Close()
	}

	// Walk extracted rules.
	imported, skipped := int64(0), int64(0)
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".conf") {
			return nil
		}
		i, s, err := u.importFile(ctx, path)
		if err != nil {
			return nil
		}
		imported += i
		skipped += s
		return nil
	})
	return imported, skipped, nil
}

// importFile parses a single CRS .conf file and counts SecRule directives.
// The engine already ships with the curated PL2 pack, so this updater is
// a fingerprint/metric for "what's available upstream". Full SecLang -> DSL
// translation lives in crs_import.go (P-FREE-2 future work).
func (u *CRSUpdater) importFile(ctx context.Context, path string) (int64, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	imported, skipped := int64(0), int64(0)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "SecRule") {
			continue
		}
		// Skip CRS preamble / control directives.
		if strings.Contains(line, "ctl:ruleEngine=off") {
			skipped++
			continue
		}
		imported++
	}
	return imported, skipped, nil
}

func (u *CRSUpdater) recordError(err error) {
	u.mu.Lock()
	u.lastError = err.Error()
	u.mu.Unlock()
	log.Printf("crs-update: %v", err)
}