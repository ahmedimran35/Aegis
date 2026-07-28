package rules

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestRequest is a sample request for rule testing.
type TestRequest struct {
	Method    string            `json:"method"`
	Path      string            `json:"path"`
	Query     string            `json:"query"`
	Headers   map[string]string `json:"headers"`
	Body      string            `json:"body"`
	UserAgent string            `json:"user_agent"`
	ClientIP  string            `json:"client_ip"`
}

// TestResult holds the outcome of testing a rule.
type TestResult struct {
	Matched      bool   `json:"matched"`
	Action       string `json:"action"`
	RuleName     string `json:"rule_name,omitempty"`
	RuleID       int    `json:"rule_id,omitempty"`
	MatchedOn    string `json:"matched_on,omitempty"`
	ResponseCode int    `json:"response_code"`
}

// Tester handles rule testing against sample requests.
type Tester struct {
	pool   *pgxpool.Pool
	engine *Engine
}

// NewTester creates a rule tester.
func NewTester(pool *pgxpool.Pool, engine *Engine) *Tester {
	return &Tester{
		pool:   pool,
		engine: engine,
	}
}

// Engine returns the underlying rule engine.
func (t *Tester) Engine() *Engine {
	return t.engine
}

// TestRule tests a specific rule against a sample request.
func (t *Tester) TestRule(ctx context.Context, ruleID int, req TestRequest) (*TestResult, error) {
	// Get the rule
	var rule Rule
	var mt, act string
	err := t.pool.QueryRow(ctx,
		`SELECT id, name, pattern, match_type, action, severity, priority, source, COALESCE(description,'')
		 FROM rules WHERE id = $1`, ruleID).Scan(
		&rule.ID, &rule.Name, &rule.Pattern, &mt, &act, &rule.Severity, &rule.Priority, &rule.Source, &rule.Description)
	if err != nil {
		return nil, err
	}
	rule.MatchType = MatchType(mt)
	rule.Action = Action(act)

	// Compile pattern
	switch rule.MatchType {
	case MatchRegex:
		re, err := compileRegex(rule.Pattern)
		if err != nil {
			return nil, err
		}
		rule.compiled = re
	case MatchCIDR:
		_, network, err := net.ParseCIDR(rule.Pattern)
		if err != nil {
			ip := net.ParseIP(rule.Pattern)
			if ip != nil {
				if ip.To4() != nil {
					_, network, _ = net.ParseCIDR(rule.Pattern + "/32")
				} else {
					_, network, _ = net.ParseCIDR(rule.Pattern + "/128")
				}
			}
		}
		rule.network = network
	}

	// Evaluate against request
	reqStr := req.Method + " " + req.Path + "?" + req.Query
	clientIP := net.ParseIP(req.ClientIP)

	matched := false
	matchedOn := ""

	switch rule.MatchType {
	case MatchRegex:
		if rule.compiled.MatchString(reqStr) {
			matched = true
			matchedOn = "request_line"
		} else if rule.compiled.MatchString(req.UserAgent) {
			matched = true
			matchedOn = "user_agent"
		} else if rule.compiled.MatchString(req.Body) {
			matched = true
			matchedOn = "body"
		}
	case MatchString:
		if containsIgnoreCase(reqStr, rule.Pattern) {
			matched = true
			matchedOn = "request_line"
		} else if containsIgnoreCase(req.UserAgent, rule.Pattern) {
			matched = true
			matchedOn = "user_agent"
		} else if containsIgnoreCase(req.Body, rule.Pattern) {
			matched = true
			matchedOn = "body"
		}
	case MatchCIDR:
		if clientIP != nil && rule.network != nil && rule.network.Contains(clientIP) {
			matched = true
			matchedOn = "client_ip"
		}
	}

	result := &TestResult{
		Matched:   matched,
		Action:    string(rule.Action),
		RuleName:  rule.Name,
		RuleID:    rule.ID,
		MatchedOn: matchedOn,
	}

	if matched && rule.Action == ActionBlock {
		result.ResponseCode = 403
	} else {
		result.ResponseCode = 200
	}

	// Save test result
	t.saveTestResult(ctx, ruleID, req, result)

	return result, nil
}

// TestAllRules tests all enabled rules against a sample request.
func (t *Tester) TestAllRules(ctx context.Context, req TestRequest) []TestResult {
	clientIP := net.ParseIP(req.ClientIP)
	reqStr := req.Method + " " + req.Path + "?" + req.Query

	results := []TestResult{}
	t.engine.mu.RLock()
	defer t.engine.mu.RUnlock()

	for i := range t.engine.rules {
		rule := &t.engine.rules[i]
		matched := false
		matchedOn := ""

		switch rule.MatchType {
		case MatchRegex:
			if rule.compiled.MatchString(reqStr) {
				matched = true
				matchedOn = "request_line"
			} else if rule.compiled.MatchString(req.UserAgent) {
				matched = true
				matchedOn = "user_agent"
			} else if rule.compiled.MatchString(req.Body) {
				matched = true
				matchedOn = "body"
			}
		case MatchString:
			if containsIgnoreCase(reqStr, rule.Pattern) {
				matched = true
				matchedOn = "request_line"
			} else if containsIgnoreCase(req.UserAgent, rule.Pattern) {
				matched = true
				matchedOn = "user_agent"
			} else if containsIgnoreCase(req.Body, rule.Pattern) {
				matched = true
				matchedOn = "body"
			}
		case MatchCIDR:
			if clientIP != nil && rule.network != nil && rule.network.Contains(clientIP) {
				matched = true
				matchedOn = "client_ip"
			}
		}

		if matched {
			results = append(results, TestResult{
				Matched:   true,
				Action:    string(rule.Action),
				RuleName:  rule.Name,
				RuleID:    rule.ID,
				MatchedOn: matchedOn,
			})
		}
	}

	return results
}

func (t *Tester) saveTestResult(ctx context.Context, ruleID int, req TestRequest, result *TestResult) {
	reqJSON, _ := json.Marshal(req)
	resultJSON, _ := json.Marshal(result)

	if _, err := t.pool.Exec(ctx,
		`INSERT INTO rule_tests (rule_id, test_request, result, passed) VALUES ($1, $2, $3, $4)`,
		ruleID, reqJSON, resultJSON, result.Matched); err != nil {
		log.Printf("rule testing: save result: %v", err)
	}
}

// GetTestHistory returns test history for a rule.
func (t *Tester) GetTestHistory(ctx context.Context, ruleID int, limit int) ([]map[string]interface{}, error) {
	rows, err := t.pool.Query(ctx,
		`SELECT id, test_request, result, passed, created_at
		 FROM rule_tests WHERE rule_id = $1 ORDER BY created_at DESC LIMIT $2`, ruleID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tests []map[string]interface{}
	for rows.Next() {
		var id int
		var reqJSON, resultJSON []byte
		var passed bool
		var createdAt time.Time

		if err := rows.Scan(&id, &reqJSON, &resultJSON, &passed, &createdAt); err != nil {
			continue
		}

		var req, result interface{}
		if err := json.Unmarshal(reqJSON, &req); err != nil {
			log.Printf("rule testing: unmarshal request: %v", err)
		}
		if err := json.Unmarshal(resultJSON, &result); err != nil {
			log.Printf("rule testing: unmarshal result: %v", err)
		}

		tests = append(tests, map[string]interface{}{
			"id":         id,
			"request":    req,
			"result":     result,
			"passed":     passed,
			"created_at": createdAt,
		})
	}

	return tests, nil
}
