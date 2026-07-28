package rules

import (
	"context"
	"log"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// MatchType defines how the rule pattern is matched.
type MatchType string

const (
	MatchRegex  MatchType = "regex"
	MatchString MatchType = "string"
	MatchCIDR   MatchType = "cidr"
)

// Action defines what happens when a rule matches.
type Action string

const (
	ActionBlock   Action = "block"
	ActionAllow   Action = "allow"
	ActionLogOnly Action = "log"
)

// Rule represents a compiled Aegis rule.
type Rule struct {
	ID            int
	Name          string
	Pattern       string
	MatchType     MatchType
	Action        Action
	Severity      string
	Priority      int
	Source        string
	Description   string
	ParanoiaLevel int      // 1-4, higher = more aggressive
	Transforms    []string // input transforms to apply before matching
	// compiled holds the pre-compiled regex (only for MatchRegex type)
	compiled *regexp.Regexp
	// network holds the parsed CIDR (only for MatchCIDR type)
	network *net.IPNet
	// patternLower holds the lowercased Pattern for MatchString
	// matching. L-10: precomputed once at load time so containsIgnoreCase
	// only lowercases the input on each match, not the pattern.
	patternLower string
}

// SeverityScore returns the anomaly score for a rule's severity.
func (r *Rule) SeverityScore() int {
	switch r.Severity {
	case "critical":
		return 10
	case "high":
		return 5
	case "medium":
		return 3
	case "low":
		return 1
	default:
		return 0
	}
}

// MatchResult holds the outcome of a rule check.
type MatchResult struct {
	Matched     bool
	Rule        *Rule    // first matched rule (for backward compat)
	Action      Action
	Score       int      // total anomaly score
	MatchedRules []Rule  // all rules that matched
}

// Engine loads rules from Postgres and evaluates requests.
type Engine struct {
	pool    *pgxpool.Pool
	mu      sync.RWMutex
	rules   []Rule
	stopCh  chan struct{}
}

// NewEngine creates a rule engine that reloads rules from DB every interval.
func NewEngine(pool *pgxpool.Pool, refreshInterval time.Duration) *Engine {
	e := &Engine{
		pool:   pool,
		stopCh: make(chan struct{}),
	}
	e.loadRules(context.Background())
	go e.refreshLoop(refreshInterval)
	return e
}

func (e *Engine) refreshLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			// M-14: derive a context from a parent that is canceled when
			// the engine is stopped, so an in-flight rule reload does not
			// outlive graceful shutdown.
			ctx, cancel := context.WithCancel(context.Background())
			go func() {
				select {
				case <-e.stopCh:
					cancel()
				case <-ctx.Done():
				}
			}()
			e.loadRules(ctx)
			cancel()
		case <-e.stopCh:
			return
		}
	}
}

// stopContext returns a context that is canceled when the engine stops,
// used by background goroutines to break out of long DB calls on
// shutdown. M-14.
func (e *Engine) stopContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		select {
		case <-e.stopCh:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

func (e *Engine) loadRules(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()

	rows, err := e.pool.Query(ctx,
		`SELECT id, name, pattern, match_type, action, severity, priority, source, COALESCE(description, ''),
		 COALESCE(paranoia_level, 1), COALESCE(transforms, '')
		 FROM rules
		 WHERE enabled = true
		 ORDER BY priority ASC`)
	if err != nil {
		log.Printf("rules: load: %v", err)
		return
	}
	defer rows.Close()

	var rules []Rule
	for rows.Next() {
		var r Rule
		var mt, act, transformsStr string
		if err := rows.Scan(&r.ID, &r.Name, &r.Pattern, &mt, &act, &r.Severity, &r.Priority, &r.Source, &r.Description,
			&r.ParanoiaLevel, &transformsStr); err != nil {
			log.Printf("rules: scan: %v", err)
			continue
		}
		r.MatchType = MatchType(mt)
		r.Action = Action(act)
		r.Transforms = ParseTransformNames(transformsStr)

		switch r.MatchType {
		case MatchRegex:
			// ReDoS gate: skip patterns with nested quantifier or quantified
			// alternation. We never persist them so they cannot re-enter the
			// engine on the next Reload().
			if err := HasReDoSRisk(r.Pattern); err != nil {
				log.Printf("rules: ReDoS reject %q (rule %d): %v", r.Pattern, r.ID, err)
				continue
			}
			re, err := regexp.Compile(r.Pattern)
			if err != nil {
				log.Printf("rules: compile regex %q (rule %d): %v", r.Pattern, r.ID, err)
				continue
			}
			r.compiled = re
		case MatchString:
			// L-10: precompute lowercase pattern once per reload.
			r.patternLower = strings.ToLower(r.Pattern)
		case MatchCIDR:
			_, network, err := net.ParseCIDR(r.Pattern)
			if err != nil {
				ip := net.ParseIP(r.Pattern)
				if ip == nil {
					log.Printf("rules: parse CIDR %q (rule %d): %v", r.Pattern, r.ID, err)
					continue
				}
				if ip.To4() != nil {
					_, network, _ = net.ParseCIDR(r.Pattern + "/32")
				} else {
					_, network, _ = net.ParseCIDR(r.Pattern + "/128")
				}
			}
			r.network = network
		}

		rules = append(rules, r)
	}

	e.mu.Lock()
	e.rules = rules
	e.mu.Unlock()
	log.Printf("rules: loaded %d rules", len(rules))
}

// Reload forces an immediate rule reload from the database.
func (e *Engine) Reload() {
	e.loadRules(context.Background())
}

// Stop halts the background refresh loop.
func (e *Engine) Stop() {
	close(e.stopCh)
}

// Evaluate checks a request against all rules. Returns first match.
// body is the raw request body content (may be empty).
// decodedQuery is the URL-decoded query string (may be empty).
// paranoiaLevel filters rules: only rules with ParanoiaLevel <= paranoiaLevel
// are evaluated (matches EvaluateAll semantics).
func (e *Engine) Evaluate(clientIP net.IP, method, path, query, userAgent, body, decodedQuery string, paranoiaLevel int) *MatchResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	reqStr := method + " " + path + "?" + query
	var reqStrDecoded string
	if decodedQuery != "" && decodedQuery != query {
		reqStrDecoded = method + " " + path + "?" + decodedQuery
	}

	// P-FIX: copy the rule value into a local variable. The previous
	// code took a pointer into the underlying slice; if a reload
	// re-allocated the slice while Evaluate was running, the pointer would
	// be left dangling or racing with the writer. The local copy is
	// immune to that race.
	for i := range e.rules {
		r := e.rules[i]

		// Filter by paranoia level (matches EvaluateAll)
		if r.ParanoiaLevel > paranoiaLevel {
			continue
		}

		// Build inputs to check (raw + transformed)
		inputs := []string{reqStr, userAgent}
		if reqStrDecoded != "" {
			inputs = append(inputs, reqStrDecoded)
		}
		if body != "" {
			inputs = append(inputs, body)
		}

		// Apply transforms if configured (matches EvaluateAll)
		if len(r.Transforms) > 0 {
			var transformed []string
			for _, inp := range inputs {
				transformed = append(transformed, ApplyTransforms(inp, r.Transforms))
			}
			inputs = append(inputs, transformed...)
		}

		matched := false
		switch r.MatchType {
		case MatchRegex:
			for _, inp := range inputs {
				if r.compiled.MatchString(inp) {
					matched = true
					break
				}
			}
		case MatchString:
			for _, inp := range inputs {
				if containsIgnoreCase(inp, r.patternLower) {
					matched = true
					break
				}
			}
		case MatchCIDR:
			if clientIP != nil && r.network != nil {
				matched = r.network.Contains(clientIP)
			}
		}

		if matched {
			return &MatchResult{
				Matched: true,
				Rule:    &r,
				Action:  r.Action,
			}
		}
	}

	return &MatchResult{Matched: false}
}

// EvaluateAll checks a request against ALL rules, accumulating an anomaly score.
// Only rules with paranoia_level <= requestedParanoiaLevel are evaluated.
// Returns all matched rules and the total score.
func (e *Engine) EvaluateAll(clientIP net.IP, method, path, query, userAgent, body, decodedQuery string, paranoiaLevel int) *MatchResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	reqStr := method + " " + path + "?" + query
	var reqStrDecoded string
	if decodedQuery != "" && decodedQuery != query {
		reqStrDecoded = method + " " + path + "?" + decodedQuery
	}

	result := &MatchResult{Matched: false}

	// P-FIX: copy the rule value into a local variable. The previous
	// code took a pointer into the underlying slice; if a reload
	// re-allocated the slice while Evaluate was running, the pointer would
	// be left dangling or racing with the writer. The local copy is
	// immune to that race.
	for i := range e.rules {
		r := e.rules[i]

		// Filter by paranoia level
		if r.ParanoiaLevel > paranoiaLevel {
			continue
		}

		// Build inputs to check (raw + transformed)
		inputs := []string{reqStr, userAgent}
		if reqStrDecoded != "" {
			inputs = append(inputs, reqStrDecoded)
		}
		if body != "" {
			inputs = append(inputs, body)
		}

		// Apply transforms if configured
		if len(r.Transforms) > 0 {
			var transformed []string
			for _, inp := range inputs {
				transformed = append(transformed, ApplyTransforms(inp, r.Transforms))
			}
			// Check both raw and transformed
			inputs = append(inputs, transformed...)
		}

		matched := false
		switch r.MatchType {
		case MatchRegex:
			for _, inp := range inputs {
				if r.compiled.MatchString(inp) {
					matched = true
					break
				}
			}
		case MatchString:
			for _, inp := range inputs {
				if containsIgnoreCase(inp, r.patternLower) {
					matched = true
					break
				}
			}
		case MatchCIDR:
			if clientIP != nil && r.network != nil {
				matched = r.network.Contains(clientIP)
			}
		}

		if matched {
			score := r.SeverityScore()
			result.Score += score
			result.MatchedRules = append(result.MatchedRules, r)
			if !result.Matched {
				result.Matched = true
				result.Rule = &r
				result.Action = r.Action
			}
		}
	}

	return result
}

// CompiledRegex returns the compiled regex for regex-type rules.
func (r *Rule) CompiledRegex() *regexp.Regexp {
	return r.compiled
}

// Network returns the parsed CIDR network for CIDR-type rules.
func (r *Rule) Network() *net.IPNet {
	return r.network
}

// Count returns the number of loaded rules.
func (e *Engine) Count() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.rules)
}

func containsIgnoreCase(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
outer:
	for i := 0; i <= len(s)-len(substr); i++ {
		for j := 0; j < len(substr); j++ {
			sc := s[i+j]
			tc := substr[j]
			if sc >= 'A' && sc <= 'Z' {
				sc += 32
			}
			if tc >= 'A' && tc <= 'Z' {
				tc += 32
			}
			if sc != tc {
				continue outer
			}
		}
		return true
	}
	return false
}
