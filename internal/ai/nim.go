package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	wafrules "github.com/user/waf/internal/rules"
)

// NIMConfig holds NIM client configuration.
type NIMConfig struct {
	APIKey  string
	Model   string
	BaseURL string
	Timeout time.Duration
}

// NIMClient implements AIService using NVIDIA NIM cloud API.
type NIMClient struct {
	cfg    NIMConfig
	client *http.Client

	// Success rate tracking
	mu      sync.RWMutex
	success []time.Time
	failure []time.Time
	window  time.Duration
}

// NewNIMClient creates a new NIM client.
func NewNIMClient(cfg NIMConfig) *NIMClient {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://integrate.api.nvidia.com/v1"
	}
	if cfg.Model == "" {
		cfg.Model = "meta/llama-3.1-8b-instruct"
	}
	if cfg.Timeout < 30*time.Second {
		cfg.Timeout = 30 * time.Second
	}
	return &NIMClient{
		cfg: cfg,
		client: &http.Client{
			Timeout: cfg.Timeout,
		},
		window: 5 * time.Minute,
	}
}

// UpdateConfig hot-reloads NIM configuration.
func (c *NIMClient) UpdateConfig(apiKey, model, baseURL string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if apiKey != "" {
		c.cfg.APIKey = apiKey
	}
	if model != "" {
		c.cfg.Model = model
	}
	if baseURL != "" {
		c.cfg.BaseURL = baseURL
	}
	c.client.Timeout = c.cfg.Timeout
}

// ListModels fetches available models from NIM API.
func (c *NIMClient) ListModels(ctx context.Context) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	c.mu.RLock()
	baseURL := c.cfg.BaseURL
	apiKey := c.cfg.APIKey
	c.mu.RUnlock()

	url := strings.TrimRight(baseURL, "/") + "/models"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nim request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("nim returned status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	var models []string
	for _, m := range result.Data {
		if m.ID != "" {
			models = append(models, m.ID)
		}
	}
	return models, nil
}

// ChatMessage is a conversation message for multi-turn chat.
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Chat sends a multi-turn conversation to NIM and returns the response.
func (c *NIMClient) Chat(ctx context.Context, systemPrompt string, messages []ChatMessage) (string, error) {
	c.mu.RLock()
	timeout := c.cfg.Timeout
	model := c.cfg.Model
	baseURL := c.cfg.BaseURL
	apiKey := c.cfg.APIKey
	c.mu.RUnlock()

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	allMessages := []chatMessage{{Role: "system", Content: systemPrompt}}
	for _, m := range messages {
		allMessages = append(allMessages, chatMessage{Role: m.Role, Content: m.Content})
	}

	reqBody := chatRequest{
		Model:       model,
		Messages:    allMessages,
		MaxTokens:   2048,
		Temperature: 0.7,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	url := strings.TrimRight(baseURL, "/") + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := c.client.Do(req)
	if err != nil {
		c.recordFailure()
		return "", fmt.Errorf("nim request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.recordFailure()
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		errMsg := string(respBody)
		log.Printf("nim: error status %d: %s", resp.StatusCode, errMsg)
		switch {
		case resp.StatusCode == 401 || strings.Contains(errMsg, "authorization"):
			return "", fmt.Errorf("NIM API key is invalid or missing — configure in Settings → AI")
		case resp.StatusCode == 429:
			return "", fmt.Errorf("NIM rate limit exceeded — try again in a few seconds")
		case resp.StatusCode == 404:
			return "", fmt.Errorf("NIM model '%s' not found — check available models in Settings → AI", model)
		case resp.StatusCode >= 500:
			return "", fmt.Errorf("NIM server error (%d) — service may be temporarily unavailable", resp.StatusCode)
		default:
			return "", fmt.Errorf("NIM request failed with status %d: %s", resp.StatusCode, errMsg)
		}
	}

	var chatResp chatResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&chatResp); err != nil {
		c.recordFailure()
		return "", fmt.Errorf("decode response: %w", err)
	}

	if len(chatResp.Choices) == 0 {
		c.recordFailure()
		return "", fmt.Errorf("nim returned no choices")
	}

	c.recordSuccess()
	return chatResp.Choices[0].Message.Content, nil
}

// chatMessage is the NIM chat completion request format.
type chatRequest struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
	MaxTokens int          `json:"max_tokens"`
	Temperature float64    `json:"temperature"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

func (c *NIMClient) complete(ctx context.Context, prompt string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	c.mu.RLock()
	model := c.cfg.Model
	baseURL := c.cfg.BaseURL
	apiKey := c.cfg.APIKey
	c.mu.RUnlock()

	reqBody := chatRequest{
		Model: model,
		Messages: []chatMessage{
			{Role: "system", Content: "You are a security analysis AI. Respond only with valid JSON as requested."},
			{Role: "user", Content: prompt},
		},
		MaxTokens:  512,
		Temperature: 0.1,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	url := strings.TrimRight(baseURL, "/") + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := c.client.Do(req)
	if err != nil {
		c.recordFailure()
		return "", fmt.Errorf("nim request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.recordFailure()
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		errMsg := string(respBody)
		log.Printf("nim: error status %d: %s", resp.StatusCode, errMsg)
		switch {
		case resp.StatusCode == 401 || strings.Contains(errMsg, "authorization"):
			return "", fmt.Errorf("NIM API key is invalid or missing — configure in Settings → AI")
		case resp.StatusCode == 429:
			return "", fmt.Errorf("NIM rate limit exceeded — try again in a few seconds")
		case resp.StatusCode == 404:
			return "", fmt.Errorf("NIM model '%s' not found — check available models in Settings → AI", model)
		case resp.StatusCode >= 500:
			return "", fmt.Errorf("NIM server error (%d) — service may be temporarily unavailable", resp.StatusCode)
		default:
			return "", fmt.Errorf("NIM request failed with status %d: %s", resp.StatusCode, errMsg)
		}
	}

	var chatResp chatResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&chatResp); err != nil {
		c.recordFailure()
		return "", fmt.Errorf("decode response: %w", err)
	}

	if len(chatResp.Choices) == 0 {
		c.recordFailure()
		return "", fmt.Errorf("nim returned no choices")
	}

	c.recordSuccess()
	return chatResp.Choices[0].Message.Content, nil
}

func (c *NIMClient) recordSuccess() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.success = append(c.success, time.Now())
	// Prune entries older than the tracking window to prevent unbounded growth
	cutoff := time.Now().Add(-c.window)
	i := 0
	for i < len(c.success) && !c.success[i].After(cutoff) {
		i++
	}
	c.success = c.success[i:]
}

func (c *NIMClient) recordFailure() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failure = append(c.failure, time.Now())
	// Prune entries older than the tracking window to prevent unbounded growth
	cutoff := time.Now().Add(-c.window)
	i := 0
	for i < len(c.failure) && !c.failure[i].After(cutoff) {
		i++
	}
	c.failure = c.failure[i:]
}

// SuccessRate returns NIM success rate over the tracking window.
func (c *NIMClient) SuccessRate() float64 {
	c.mu.Lock()
	defer c.mu.Unlock()

	cutoff := time.Now().Add(-c.window)
	s, f := 0, 0
	for _, t := range c.success {
		if t.After(cutoff) {
			s++
		}
	}
	for _, t := range c.failure {
		if t.After(cutoff) {
			f++
		}
	}
	total := s + f
	if total == 0 {
		return 1.0 // no requests yet — assume healthy
	}
	return float64(s) / float64(total)
}

// sanitizeForPrompt strips injection patterns from user-controlled strings
// before they are embedded in an AI prompt.
func sanitizeForPrompt(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	s = strings.ReplaceAll(s, "\x00", "")
	s = strings.ReplaceAll(s, "\u2028", " ") // Unicode line separator
	s = strings.ReplaceAll(s, "\u2029", " ") // Unicode paragraph separator
	s = strings.ReplaceAll(s, "```", "")
	s = strings.ReplaceAll(s, "---", "")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// ClassifyRequest evaluates a request for threats.
func (c *NIMClient) ClassifyRequest(ctx context.Context, features RequestFeatures) (*Classification, error) {
	c.mu.RLock()
	timeout := c.cfg.Timeout
	c.mu.RUnlock()

	prompt := fmt.Sprintf(`Analyze this HTTP request for security threats.
Request: %s %s?%s
Content-Type: %s
User-Agent: %s
Client IP: %s (%s)
Body hash: %s

Respond with JSON:
{"score": 0.0-1.0, "classification": "benign|suspicious|malicious", "reasoning": "..."}`,
		sanitizeForPrompt(features.Method),
		sanitizeForPrompt(features.Path),
		sanitizeForPrompt(features.QueryParams),
		sanitizeForPrompt(features.ContentType),
		sanitizeForPrompt(features.UserAgent),
		sanitizeForPrompt(features.ClientIP),
		sanitizeForPrompt(features.Country),
		sanitizeForPrompt(features.BodyHash))

	raw, err := c.complete(ctx, prompt, timeout)
	if err != nil {
		return nil, err
	}

	return parseClassification(raw)
}

// DetectAnomaly analyzes traffic stats.
func (c *NIMClient) DetectAnomaly(ctx context.Context, stats TrafficStats) (*AnomalyResult, error) {
	c.mu.RLock()
	timeout := c.cfg.Timeout
	c.mu.RUnlock()

	statsJSON, _ := json.Marshal(stats)
	prompt := fmt.Sprintf(`Analyze these traffic stats for anomalies:
%s

Respond with JSON:
{"has_anomaly": true/false, "anomalies": [{"type": "...", "severity": "...", "description": "...", "confidence": 0.0-1.0}]}`, string(statsJSON))

	raw, err := c.complete(ctx, prompt, timeout)
	if err != nil {
		return nil, err
	}

	return parseAnomalyResult(raw)
}

// GenerateRule creates a rule from attack patterns.
func (c *NIMClient) GenerateRule(ctx context.Context, attacks []AttackPattern) (*GeneratedRule, error) {
	c.mu.RLock()
	timeout := c.cfg.Timeout
	c.mu.RUnlock()

	// Sanitize attack strings before marshalling to prevent prompt injection
	sanitized := make([]AttackPattern, len(attacks))
	for i, a := range attacks {
		sanitized[i] = a
		sanExamples := make([]string, len(a.Examples))
		for j, ex := range a.Examples {
			sanExamples[j] = sanitizeForPrompt(ex)
		}
		sanitized[i].Examples = sanExamples
		sanitized[i].Category = sanitizeForPrompt(a.Category)
	}
	attacksJSON, _ := json.Marshal(sanitized)
	prompt := fmt.Sprintf(`Generate an Aegis rule to block these attack patterns:
%s

Respond with JSON:
{"pattern": "...", "match_type": "regex|string|cidr", "suggested_action": "block|allow|log", "confidence": 0.0-1.0, "description": "..."}`, sanitizeForPrompt(string(attacksJSON)))

	raw, err := c.complete(ctx, prompt, timeout)
	if err != nil {
		return nil, err
	}

	return parseGeneratedRule(raw)
}

// AnalyzeLogs performs NL analysis on logs.
func (c *NIMClient) AnalyzeLogs(ctx context.Context, query string) (*AnalysisResult, error) {
	c.mu.RLock()
	timeout := c.cfg.Timeout
	c.mu.RUnlock()

	prompt := fmt.Sprintf(`Analyze these Aegis logs and answer the question: %s

Respond with JSON:
{"summary": "...", "findings": ["..."], "suggestions": ["..."]}`, sanitizeForPrompt(query))

	raw, err := c.complete(ctx, prompt, timeout)
	if err != nil {
		return nil, err
	}

	return parseAnalysisResult(raw)
}

// parseClassification extracts Classification from LLM JSON response.
func parseClassification(raw string) (*Classification, error) {
	raw = extractJSON(raw)
	var c Classification
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		log.Printf("ai: parse classification: %v (raw: %s)", err, raw)
		return &Classification{Score: 0, Classification: "benign", Reasoning: "parse error"}, nil
	}
	// Validate score bounds (must be 0.0-1.0)
	if c.Score < 0 {
		c.Score = 0
	}
	if c.Score > 1 {
		c.Score = 1
	}
	// Validate classification enum
	validClasses := map[string]bool{"benign": true, "suspicious": true, "malicious": true}
	if !validClasses[c.Classification] {
		c.Classification = "suspicious"
	}
	return &c, nil
}

func parseAnomalyResult(raw string) (*AnomalyResult, error) {
	raw = extractJSON(raw)
	var r AnomalyResult
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return nil, fmt.Errorf("parse anomaly: %w", err)
	}
	return &r, nil
}

func parseGeneratedRule(raw string) (*GeneratedRule, error) {
	raw = extractJSON(raw)
	var r GeneratedRule
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return nil, fmt.Errorf("parse rule: %w", err)
	}
	// Validate pattern length to prevent ReDoS
	if len(r.Pattern) > 500 {
		return nil, fmt.Errorf("rule pattern too long (%d chars, max 500)", len(r.Pattern))
	}
	// Validate MatchType enum
	validMatchTypes := map[string]bool{"regex": true, "string": true, "cidr": true}
	if !validMatchTypes[r.MatchType] {
		return nil, fmt.Errorf("invalid match_type: %s", r.MatchType)
	}
	// Validate SuggestedAction enum
	validActions := map[string]bool{"block": true, "allow": true, "log": true}
	if !validActions[r.SuggestedAction] {
		return nil, fmt.Errorf("invalid suggested_action: %s", r.SuggestedAction)
	}
	// Test-compile regex patterns + ReDoS check to catch invalid OR catastrophic patterns
	if r.MatchType == "regex" && r.Pattern != "" {
		if err := wafrules.HasReDoSRisk(r.Pattern); err != nil {
			return nil, fmt.Errorf("unsafe regex pattern: %w", err)
		}
		if _, err := regexp.Compile(r.Pattern); err != nil {
			return nil, fmt.Errorf("invalid regex pattern: %w", err)
		}
	}
	// Validate CIDR patterns
	if r.MatchType == "cidr" && r.Pattern != "" {
		if _, _, err := net.ParseCIDR(r.Pattern); err != nil {
			return nil, fmt.Errorf("invalid CIDR pattern: %w", err)
		}
	}
	// Validate confidence bounds
	if r.Confidence < 0 {
		r.Confidence = 0
	}
	if r.Confidence > 1 {
		r.Confidence = 1
	}
	return &r, nil
}

func parseAnalysisResult(raw string) (*AnalysisResult, error) {
	raw = extractJSON(raw)
	var r AnalysisResult
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return nil, fmt.Errorf("parse analysis: %w", err)
	}
	return &r, nil
}

// extractJSON pulls JSON from text that may contain markdown code fences.
func extractJSON(s string) string {
	s = strings.TrimSpace(s)
	// Strip markdown code fence
	if strings.HasPrefix(s, "```json") {
		s = strings.TrimPrefix(s, "```json")
		s = strings.TrimSuffix(s, "```")
		s = strings.TrimSpace(s)
	} else if strings.HasPrefix(s, "```") {
		s = strings.TrimPrefix(s, "```")
		s = strings.TrimSuffix(s, "```")
		s = strings.TrimSpace(s)
	}
	// Find first { and last }
	start := strings.Index(s, "{")
	end := strings.LastIndex(s, "}")
	if start >= 0 && end > start {
		return s[start : end+1]
	}
	return s
}
