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

// OllamaConfig holds Ollama client configuration.
type OllamaConfig struct {
	URL     string
	Model   string
	Timeout time.Duration
}

// OllamaClient implements AIService using a local Ollama instance.
type OllamaClient struct {
	cfg    OllamaConfig
	client *http.Client
	mu     sync.RWMutex
}

// NewOllamaClient creates a new Ollama client.
func NewOllamaClient(cfg OllamaConfig) *OllamaClient {
	if cfg.URL == "" {
		cfg.URL = "http://ollama:11434"
	}
	if cfg.Model == "" {
		cfg.Model = "llama3:8b"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}
	return &OllamaClient{
		cfg:    cfg,
		client: &http.Client{Timeout: cfg.Timeout},
	}
}

type ollamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
	Format string `json:"format,omitempty"`
}

type ollamaResponse struct {
	Response string `json:"response"`
}

type ollamaChatRequest struct {
	Model    string          `json:"model"`
	Messages []ChatMessage   `json:"messages"`
	Stream   bool            `json:"stream"`
	Format   string          `json:"format,omitempty"`
}

type ollamaChatResponse struct {
	Message struct {
		Content string `json:"content"`
	} `json:"message"`
}

// Chat sends a multi-turn conversation to Ollama and returns the response.
func (c *OllamaClient) Chat(ctx context.Context, systemPrompt string, messages []ChatMessage) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()

	c.mu.RLock()
	model := c.cfg.Model
	url := c.cfg.URL
	c.mu.RUnlock()

	allMessages := []ChatMessage{{Role: "system", Content: systemPrompt}}
	allMessages = append(allMessages, messages...)

	reqBody := ollamaChatRequest{
		Model:    model,
		Messages: allMessages,
		Stream:   false,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(url, "/")+"/api/chat", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("ollama request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		errMsg := string(respBody)
		log.Printf("ollama: error status %d: %s", resp.StatusCode, errMsg)
		switch {
		case resp.StatusCode == 404:
			return "", fmt.Errorf("Ollama model '%s' not found — run 'ollama pull %s' on the server or change model in Settings → AI", model, model)
		case resp.StatusCode >= 500:
			return "", fmt.Errorf("Ollama server error (%d) — is Ollama running? Check 'systemctl status ollama'", resp.StatusCode)
		default:
			return "", fmt.Errorf("Ollama error %d: %s", resp.StatusCode, errMsg)
		}
	}

	var oResp ollamaChatResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&oResp); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}

	return oResp.Message.Content, nil
}

func (c *OllamaClient) generate(ctx context.Context, prompt string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	c.mu.RLock()
	model := c.cfg.Model
	ollamaURL := c.cfg.URL
	c.mu.RUnlock()

	reqBody := ollamaRequest{
		Model:  model,
		Prompt: prompt,
		Stream: false,
		Format: "json",
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	url := strings.TrimRight(ollamaURL, "/") + "/api/generate"
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("ollama request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		errMsg := string(respBody)
		log.Printf("ollama: error status %d: %s", resp.StatusCode, errMsg)
		switch {
		case resp.StatusCode == 404:
			return "", fmt.Errorf("Ollama model '%s' not found — run 'ollama pull %s' or change in Settings → AI", model, model)
		case resp.StatusCode >= 500:
			return "", fmt.Errorf("Ollama server error (%d) — is Ollama running?", resp.StatusCode)
		default:
			return "", fmt.Errorf("Ollama error %d: %s", resp.StatusCode, errMsg)
		}
	}

	var oResp ollamaResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&oResp); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}

	return oResp.Response, nil
}

// ClassifyRequest evaluates a request for threats.
func (c *OllamaClient) ClassifyRequest(ctx context.Context, features RequestFeatures) (*Classification, error) {
	c.mu.RLock()
	timeout := c.cfg.Timeout
	c.mu.RUnlock()

	prompt := fmt.Sprintf(`Analyze this HTTP request for security threats. Respond with JSON only.
Request: %s %s?%s
Content-Type: %s
User-Agent: %s
Client IP: %s (%s)
Body hash: %s

Respond with this JSON format:
{"score": 0.0, "classification": "benign", "reasoning": "..."}`,
		sanitizeForPrompt(features.Method),
		sanitizeForPrompt(features.Path),
		sanitizeForPrompt(features.QueryParams),
		sanitizeForPrompt(features.ContentType),
		sanitizeForPrompt(features.UserAgent),
		sanitizeForPrompt(features.ClientIP),
		sanitizeForPrompt(features.Country),
		sanitizeForPrompt(features.BodyHash))

	raw, err := c.generate(ctx, prompt, timeout)
	if err != nil {
		return nil, err
	}

	return parseClassification(raw)
}

// DetectAnomaly analyzes traffic stats.
func (c *OllamaClient) DetectAnomaly(ctx context.Context, stats TrafficStats) (*AnomalyResult, error) {
	statsJSON, _ := json.Marshal(stats)
	prompt := fmt.Sprintf(`Analyze these traffic stats for anomalies. Respond with JSON only.
%s

{"has_anomaly": false, "anomalies": []}`, string(statsJSON))

	raw, err := c.generate(ctx, prompt, 30*time.Second)
	if err != nil {
		return nil, err
	}

	return parseAnomalyResult(raw)
}

// GenerateRule creates a rule from attack patterns.
func (c *OllamaClient) GenerateRule(ctx context.Context, attacks []AttackPattern) (*GeneratedRule, error) {
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
	prompt := fmt.Sprintf(`Generate an Aegis rule to block these attacks. Respond with JSON only.
%s

{"pattern": "...", "match_type": "regex", "suggested_action": "block", "confidence": 0.8, "description": "..."}`, sanitizeForPrompt(string(attacksJSON)))

	raw, err := c.generate(ctx, prompt, 10*time.Second)
	if err != nil {
		return nil, err
	}

	return parseGeneratedRule(raw)
}

// SuccessRate returns 0 since Ollama doesn't track success rates.
func (c *OllamaClient) SuccessRate() float64 {
	return 0
}

// ListModels fetches available models from Ollama.
func (c *OllamaClient) ListModels(ctx context.Context) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	c.mu.RLock()
	url := c.cfg.URL
	c.mu.RUnlock()

	req, err := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(url, "/")+"/api/tags", nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ollama request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("ollama returned status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	var models []string
	for _, m := range result.Models {
		if m.Name != "" {
			models = append(models, m.Name)
		}
	}
	return models, nil
}

// UpdateConfig hot-reloads Ollama configuration. Also updates the HTTP
// client timeout so a config change in Settings takes effect immediately.
func (c *OllamaClient) UpdateConfig(url, model string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if url != "" {
		c.cfg.URL = url
	}
	if model != "" {
		c.cfg.Model = model
	}
	if c.cfg.Timeout > 0 {
		c.client.Timeout = c.cfg.Timeout
	}
}

// AnalyzeLogs performs NL analysis on logs.
func (c *OllamaClient) AnalyzeLogs(ctx context.Context, query string) (*AnalysisResult, error) {
	prompt := fmt.Sprintf(`Analyze these Aegis logs and answer: %s
Respond with JSON only.
{"summary": "...", "findings": [], "suggestions": []}`, sanitizeForPrompt(query))

	raw, err := c.generate(ctx, prompt, 15*time.Second)
	if err != nil {
		return nil, err
	}

	return parseAnalysisResult(raw)
}
