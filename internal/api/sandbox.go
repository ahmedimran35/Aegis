package api

import (
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/user/waf/internal/config"
	"github.com/user/waf/internal/rules"
)

// SandboxHandler handles the rule testing sandbox endpoint.
type SandboxHandler struct {
	engine *rules.Engine
	cfg    *config.Config
}

// NewSandboxHandler creates a sandbox handler.
func NewSandboxHandler(engine *rules.Engine, cfg *config.Config) *SandboxHandler {
	return &SandboxHandler{engine: engine, cfg: cfg}
}

// SandboxRequest is the input for sandbox testing.
type SandboxRequest struct {
	Method        string            `json:"method"`
	Path          string            `json:"path"`
	Headers       map[string]string `json:"headers"`
	Body          string            `json:"body"`
	Query         string            `json:"query"`
	ClientIP      string            `json:"client_ip"`
	ParanoiaLevel int               `json:"paranoia_level"`
}

// RuleTrigger represents a single rule that matched during sandbox testing.
type RuleTrigger struct {
	RuleID        int    `json:"rule_id"`
	Name          string `json:"name"`
	Pattern       string `json:"pattern"`
	PatternMatch  string `json:"pattern_match"`
	ScoreAdded    int    `json:"score_added"`
	Severity      string `json:"severity"`
	MatchType     string `json:"match_type"`
	Action        string `json:"action"`
	ParanoiaLevel int    `json:"paranoia_level"`
}

// ScoreBreakdown shows how the anomaly score accumulated rule by rule.
type ScoreBreakdown struct {
	RuleID       int    `json:"rule_id"`
	Name         string `json:"name"`
	RunningScore int    `json:"running_score"`
	Severity     string `json:"severity"`
	ScoreAdded   int    `json:"score_added"`
}

// SandboxResult is the response from sandbox testing.
type SandboxResult struct {
	Matched          bool             `json:"matched"`
	RulesTriggered   []RuleTrigger    `json:"rules_triggered"`
	TotalScore       int              `json:"total_score"`
	WouldBlock       bool             `json:"would_block"`
	AnomalyThreshold int              `json:"anomaly_threshold"`
	ParanoiaLevel    int              `json:"paranoia_level"`
	Classification   string           `json:"classification"`
	Breakdown        []ScoreBreakdown `json:"breakdown"`
}

// TestSandbox tests a request against all rules in dry-run mode without blocking.
func (h *SandboxHandler) TestSandbox(w http.ResponseWriter, r *http.Request) {
	var req SandboxRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_BODY", "invalid sandbox request")
		return
	}

	// Defaults
	if req.Method == "" {
		req.Method = "GET"
	}
	if req.Path == "" {
		req.Path = "/"
	}
	paranoiaLevel := req.ParanoiaLevel
	if paranoiaLevel < 1 || paranoiaLevel > 4 {
		paranoiaLevel = h.cfg.Rules.ParanoiaLevel
	}

	// Extract User-Agent from headers
	userAgent := ""
	if req.Headers != nil {
		for k, v := range req.Headers {
			if strings.EqualFold(k, "user-agent") {
				userAgent = v
				break
			}
		}
	}

	// Parse client IP
	var ip net.IP
	if req.ClientIP != "" {
		ip = net.ParseIP(req.ClientIP)
	}

	// URL-decode query
	decodedQuery, _ := url.QueryUnescape(req.Query)

	// Evaluate using the engine (dry-run — never blocks)
	result := h.engine.EvaluateAll(ip, req.Method, req.Path, req.Query, userAgent, req.Body, decodedQuery, paranoiaLevel)

	threshold := h.cfg.Rules.AnomalyThreshold

	sandboxResult := SandboxResult{
		Matched:          result.Matched,
		TotalScore:       result.Score,
		WouldBlock:       result.Score >= threshold,
		AnomalyThreshold: threshold,
		ParanoiaLevel:    paranoiaLevel,
		RulesTriggered:   []RuleTrigger{},
		Breakdown:        []ScoreBreakdown{},
	}

	// Classification
	if result.Score >= threshold {
		sandboxResult.Classification = "block"
	} else if result.Score > 0 {
		sandboxResult.Classification = "log"
	} else {
		sandboxResult.Classification = "allow"
	}

	// Build rules triggered and score breakdown
	runningScore := 0
	for _, mr := range result.MatchedRules {
		score := mr.SeverityScore()
		runningScore += score

		matchOn := sandboxDetermineMatchSource(ip, req.Method, req.Path, req.Query, userAgent, req.Body, decodedQuery, &mr)

		sandboxResult.RulesTriggered = append(sandboxResult.RulesTriggered, RuleTrigger{
			RuleID:        mr.ID,
			Name:          mr.Name,
			Pattern:       mr.Pattern,
			PatternMatch:  matchOn,
			ScoreAdded:    score,
			Severity:      mr.Severity,
			MatchType:     string(mr.MatchType),
			Action:        string(mr.Action),
			ParanoiaLevel: mr.ParanoiaLevel,
		})

		sandboxResult.Breakdown = append(sandboxResult.Breakdown, ScoreBreakdown{
			RuleID:       mr.ID,
			Name:         mr.Name,
			RunningScore: runningScore,
			Severity:     mr.Severity,
			ScoreAdded:   score,
		})
	}

	RespondJSON(w, http.StatusOK, sandboxResult)
}

// sandboxDetermineMatchSource checks which input component matched a rule.
func sandboxDetermineMatchSource(clientIP net.IP, method, path, query, userAgent, body, decodedQuery string, rule *rules.Rule) string {
	if rule.MatchType == rules.MatchCIDR {
		return "client_ip"
	}

	reqStr := method + " " + path + "?" + query
	reqStrDecoded := ""
	if decodedQuery != "" && decodedQuery != query {
		reqStrDecoded = method + " " + path + "?" + decodedQuery
	}

	checkInput := func(input string) bool {
		switch rule.MatchType {
		case rules.MatchRegex:
			if re := rule.CompiledRegex(); re != nil {
				return re.MatchString(input)
			}
		case rules.MatchString:
			return strings.Contains(strings.ToLower(input), strings.ToLower(rule.Pattern))
		}
		return false
	}

	// Check raw inputs
	if checkInput(reqStr) {
		return "request_line"
	}
	if userAgent != "" && checkInput(userAgent) {
		return "user_agent"
	}
	if reqStrDecoded != "" && checkInput(reqStrDecoded) {
		return "query_decoded"
	}
	if body != "" && checkInput(body) {
		return "body"
	}

	// Check transformed inputs
	if len(rule.Transforms) > 0 {
		if checkInput(rules.ApplyTransforms(reqStr, rule.Transforms)) {
			return "request_line (transformed)"
		}
		if userAgent != "" && checkInput(rules.ApplyTransforms(userAgent, rule.Transforms)) {
			return "user_agent (transformed)"
		}
		if reqStrDecoded != "" && checkInput(rules.ApplyTransforms(reqStrDecoded, rule.Transforms)) {
			return "query_decoded (transformed)"
		}
		if body != "" && checkInput(rules.ApplyTransforms(body, rule.Transforms)) {
			return "body (transformed)"
		}
	}

	return "unknown"
}
