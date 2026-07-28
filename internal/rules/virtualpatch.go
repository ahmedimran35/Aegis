package rules

import (
	"context"
	"log"
	"regexp"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// VirtualPatch represents a CVE-specific rule template.
type VirtualPatch struct {
	ID             int
	CVEID          string
	Name           string
	Description    string
	RulePattern    string
	MatchType      string
	Action         string
	Severity       string
	AffectedPaths  []string
	Enabled        bool
	compiledRegex *regexp.Regexp
}

// VirtualPatchEngine manages CVE-specific virtual patches.
type VirtualPatchEngine struct {
	pool   *pgxpool.Pool
	mu     sync.RWMutex
	patches []VirtualPatch
	stopCh chan struct{}
}

// NewVirtualPatchEngine creates a virtual patch engine.
func NewVirtualPatchEngine(pool *pgxpool.Pool, refreshInterval time.Duration) *VirtualPatchEngine {
	e := &VirtualPatchEngine{
		pool:   pool,
		stopCh: make(chan struct{}),
	}
	e.loadPatches()
	go e.refreshLoop(refreshInterval)
	return e
}

func (e *VirtualPatchEngine) refreshLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			e.loadPatches()
		case <-e.stopCh:
			return
		}
	}
}

func (e *VirtualPatchEngine) loadPatches() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rows, err := e.pool.Query(ctx,
		`SELECT id, cve_id, name, COALESCE(description,''), rule_pattern, match_type, action, severity, COALESCE(affected_paths, '{}'), enabled
		 FROM virtual_patches
		 WHERE enabled = true
		 ORDER BY severity DESC`)
	if err != nil {
		log.Printf("vpatch: load: %v", err)
		return
	}
	defer rows.Close()

	var patches []VirtualPatch
	for rows.Next() {
		var p VirtualPatch
		if err := rows.Scan(&p.ID, &p.CVEID, &p.Name, &p.Description, &p.RulePattern, &p.MatchType, &p.Action, &p.Severity, &p.AffectedPaths, &p.Enabled); err != nil {
			log.Printf("vpatch: scan: %v", err)
			continue
		}
		// Pre-compile regex patterns to prevent ReDoS on every request
		if p.MatchType == "regex" && p.RulePattern != "" {
			// ReDoS gate: skip, do NOT register as compiled.
			if err := HasReDoSRisk(p.RulePattern); err != nil {
				log.Printf("vpatch: ReDoS reject for %s: %v", p.Name, err)
				continue
			}
			re, err := regexp.Compile(p.RulePattern)
			if err != nil {
				log.Printf("vpatch: invalid regex pattern for %s: %v", p.Name, err)
				continue
			}
			p.compiledRegex = re
		}
		patches = append(patches, p)
	}

	e.mu.Lock()
	e.patches = patches
	e.mu.Unlock()
	log.Printf("vpatch: loaded %d virtual patches", len(patches))
}

// Evaluate checks if a request matches any virtual patch.
func (e *VirtualPatchEngine) Evaluate(path, query, body, userAgent string) *VirtualPatch {
	e.mu.RLock()
	defer e.mu.RUnlock()

	reqStr := path + "?" + query

	for i := range e.patches {
		p := &e.patches[i]

		// Check if path is in affected paths
		if len(p.AffectedPaths) > 0 {
			pathMatch := false
			for _, ap := range p.AffectedPaths {
				if containsIgnoreCase(path, ap) {
					pathMatch = true
					break
				}
			}
			if !pathMatch {
				continue
			}
		}

		switch p.MatchType {
		case "regex":
			if p.compiledRegex == nil {
				continue
			}
			if p.compiledRegex.MatchString(reqStr) || p.compiledRegex.MatchString(body) || p.compiledRegex.MatchString(userAgent) {
				return p
			}
		case "string":
			if containsIgnoreCase(reqStr, p.RulePattern) || containsIgnoreCase(body, p.RulePattern) {
				return p
			}
		}
	}
	return nil
}

// List returns all virtual patches.
func (e *VirtualPatchEngine) List() []VirtualPatch {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]VirtualPatch, len(e.patches))
	copy(result, e.patches)
	return result
}

// Stop halts the background refresh loop.
func (e *VirtualPatchEngine) Stop() {
	close(e.stopCh)
}
