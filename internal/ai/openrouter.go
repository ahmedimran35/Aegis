package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// OpenRouterConfig holds OpenRouter client configuration.
type OpenRouterConfig struct {
	APIKey  string
	Model   string
	BaseURL string
	Timeout time.Duration
}

// OpenRouterClient implements AIService using the OpenRouter API (OpenAI-compatible).
type OpenRouterClient struct {
	cfg    OpenRouterConfig
	client *http.Client

	// Success rate tracking (sliding window, same pattern as NIMClient)
	mu      sync.Mutex
	success []time.Time
	failure []time.Time
	window  time.Duration
}

// NewOpenRouterClient creates a new OpenRouter client with sensible defaults.
func NewOpenRouterClient(cfg OpenRouterConfig) *OpenRouterClient {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://openrouter.ai/api/v1"
	}
	// Normalize: ensure /v1 suffix
	cfg.BaseURL = normalizeOpenRouterURL(cfg.BaseURL)
	if cfg.Model == "" {
		cfg.Model = "openrouter/auto"
	}
	if cfg.Timeout < 30*time.Second {
		cfg.Timeout = 30 * time.Second
	}
	return &OpenRouterClient{
		cfg: cfg,
		client: &http.Client{
			Timeout: cfg.Timeout,
		},
		window: 5 * time.Minute,
	}
}

// UpdateConfig hot-reloads OpenRouter configuration.
func (c *OpenRouterClient) UpdateConfig(apiKey, model, baseURL string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if apiKey != "" {
		c.cfg.APIKey = apiKey
	}
	if model != "" {
		c.cfg.Model = model
	}
	if baseURL != "" {
		c.cfg.BaseURL = normalizeOpenRouterURL(baseURL)
	}
	c.client.Timeout = c.cfg.Timeout
}

// normalizeOpenRouterURL ensures the base URL ends with /v1
func normalizeOpenRouterURL(u string) string {
	u = strings.TrimRight(u, "/")
	if !strings.HasSuffix(u, "/v1") {
		u = u + "/v1"
	}
	return u
}

// ListModels fetches available models from the OpenRouter API.
func (c *OpenRouterClient) ListModels(ctx context.Context) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	url := strings.TrimRight(c.cfg.BaseURL, "/") + "/models"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	req.Header.Set("HTTP-Referer", "https://aegis.local")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("OpenRouter request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("OpenRouter returned status %d: %s", resp.StatusCode, string(body))
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

// Chat sends a multi-turn conversation to OpenRouter and returns the response.
func (c *OpenRouterClient) Chat(ctx context.Context, systemPrompt string, messages []ChatMessage) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()

	allMessages := []chatMessage{{Role: "system", Content: systemPrompt}}
	for _, m := range messages {
		allMessages = append(allMessages, chatMessage{Role: m.Role, Content: m.Content})
	}

	reqBody := chatRequest{
		Model:       c.cfg.Model,
		Messages:    allMessages,
		MaxTokens:   2048,
		Temperature: 0.7,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	url := strings.TrimRight(c.cfg.BaseURL, "/") + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	req.Header.Set("HTTP-Referer", "https://aegis.local")

	resp, err := c.client.Do(req)
	if err != nil {
		c.recordFailure()
		return "", fmt.Errorf("OpenRouter request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.recordFailure()
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		errMsg := string(respBody)
		log.Printf("openrouter: error status %d: %s", resp.StatusCode, errMsg)
		return "", c.classifyError(resp.StatusCode, errMsg)
	}

	var chatResp chatResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&chatResp); err != nil {
		c.recordFailure()
		return "", fmt.Errorf("decode response: %w", err)
	}

	if len(chatResp.Choices) == 0 {
		c.recordFailure()
		return "", fmt.Errorf("OpenRouter returned no choices")
	}

	c.recordSuccess()
	return chatResp.Choices[0].Message.Content, nil
}

// complete sends a single-turn completion request (used by ClassifyRequest, etc.).
func (c *OpenRouterClient) complete(ctx context.Context, prompt string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	reqBody := chatRequest{
		Model: c.cfg.Model,
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

	url := strings.TrimRight(c.cfg.BaseURL, "/") + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	req.Header.Set("HTTP-Referer", "https://aegis.local")

	resp, err := c.client.Do(req)
	if err != nil {
		c.recordFailure()
		return "", fmt.Errorf("OpenRouter request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.recordFailure()
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		errMsg := string(respBody)
		log.Printf("openrouter: error status %d: %s", resp.StatusCode, errMsg)
		return "", c.classifyError(resp.StatusCode, errMsg)
	}

	var chatResp chatResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&chatResp); err != nil {
		c.recordFailure()
		return "", fmt.Errorf("decode response: %w", err)
	}

	if len(chatResp.Choices) == 0 {
		c.recordFailure()
		return "", fmt.Errorf("OpenRouter returned no choices")
	}

	c.recordSuccess()
	return chatResp.Choices[0].Message.Content, nil
}

// classifyError maps HTTP status codes to user-friendly OpenRouter error messages.
func (c *OpenRouterClient) classifyError(statusCode int, body string) error {
	switch {
	case statusCode == 401 || strings.Contains(body, "authorization"):
		return fmt.Errorf("OpenRouter API key is invalid — configure in Settings → AI")
	case statusCode == 429:
		return fmt.Errorf("OpenRouter rate limit exceeded — try again in a few seconds")
	case statusCode == 404:
		return fmt.Errorf("OpenRouter model '%s' not found — check available models in Settings → AI", c.cfg.Model)
	case statusCode >= 500:
		return fmt.Errorf("OpenRouter server error (%d) — service may be temporarily unavailable", statusCode)
	default:
		return fmt.Errorf("OpenRouter request failed with status %d: %s", statusCode, body)
	}
}

// recordSuccess records a successful request in the sliding window.
func (c *OpenRouterClient) recordSuccess() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.success = append(c.success, time.Now())
	cutoff := time.Now().Add(-c.window)
	i := 0
	for i < len(c.success) && !c.success[i].After(cutoff) {
		i++
	}
	c.success = c.success[i:]
}

// recordFailure records a failed request in the sliding window.
func (c *OpenRouterClient) recordFailure() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failure = append(c.failure, time.Now())
	cutoff := time.Now().Add(-c.window)
	i := 0
	for i < len(c.failure) && !c.failure[i].After(cutoff) {
		i++
	}
	c.failure = c.failure[i:]
}

// SuccessRate returns OpenRouter success rate over the tracking window.
func (c *OpenRouterClient) SuccessRate() float64 {
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

// ClassifyRequest evaluates an HTTP request for security threats.
func (c *OpenRouterClient) ClassifyRequest(ctx context.Context, features RequestFeatures) (*Classification, error) {
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

	raw, err := c.complete(ctx, prompt, c.cfg.Timeout)
	if err != nil {
		return nil, err
	}

	return parseClassification(raw)
}

// DetectAnomaly analyzes traffic stats to find anomalies.
func (c *OpenRouterClient) DetectAnomaly(ctx context.Context, stats TrafficStats) (*AnomalyResult, error) {
	statsJSON, err := json.Marshal(stats)
	if err != nil {
		return nil, fmt.Errorf("marshal stats: %w", err)
	}
	prompt := fmt.Sprintf(`Analyze these traffic stats for anomalies:
%s

Respond with JSON:
{"has_anomaly": true/false, "anomalies": [{"type": "...", "severity": "...", "description": "...", "confidence": 0.0-1.0}]}`, string(statsJSON))

	raw, err := c.complete(ctx, prompt, c.cfg.Timeout)
	if err != nil {
		return nil, err
	}

	return parseAnomalyResult(raw)
}

// GenerateRule creates an Aegis rule from attack patterns.
func (c *OpenRouterClient) GenerateRule(ctx context.Context, attacks []AttackPattern) (*GeneratedRule, error) {
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
	attacksJSON, err := json.Marshal(sanitized)
	if err != nil {
		return nil, fmt.Errorf("marshal attacks: %w", err)
	}
	prompt := fmt.Sprintf(`Generate an Aegis rule to block these attack patterns:
%s

Respond with JSON:
{"pattern": "...", "match_type": "regex|string|cidr", "suggested_action": "block|allow|log", "confidence": 0.0-1.0, "description": "..."}`, sanitizeForPrompt(string(attacksJSON)))

	raw, err := c.complete(ctx, prompt, c.cfg.Timeout)
	if err != nil {
		return nil, err
	}

	return parseGeneratedRule(raw)
}

// AnalyzeLogs performs natural-language analysis on Aegis logs.
func (c *OpenRouterClient) AnalyzeLogs(ctx context.Context, query string) (*AnalysisResult, error) {
	prompt := fmt.Sprintf(`Analyze these Aegis logs and answer the question: %s

Respond with JSON:
{"summary": "...", "findings": ["..."], "suggestions": ["..."]}`, sanitizeForPrompt(query))

	raw, err := c.complete(ctx, prompt, c.cfg.Timeout)
	if err != nil {
		return nil, err
	}

	return parseAnalysisResult(raw)
}
