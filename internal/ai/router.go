package ai

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// RouterConfig holds failover configuration.
type RouterConfig struct {
	Threshold float64       // NIM success rate threshold to trigger failover
	Window    time.Duration // Sliding window for success rate calculation
}

// Router wraps NIM (primary), OpenRouter (secondary), and Ollama (fallback) with automatic failover.
type Router struct {
	nim        *NIMClient
	ollama     *OllamaClient
	openrouter *OpenRouterClient
	cfg        RouterConfig
	cost       *CostController // optional budget gate; nil = unlimited
	redactor   *PIIRedactor    // optional PII scrub; nil = no-op

	mu            sync.RWMutex
	useOllama     bool
	useOpenRouter bool
	provider      string // "nim", "ollama", or "auto" (default)
	lastSuccessAt time.Time
	lastErrAt     time.Time
	lastErrMsg    string
	stopCh        chan struct{}
	stopOnce      sync.Once
}

// SetCostController wires a budget gate. When wired, ClassifyRequest will
// reject callers exceeding MaxTokensPerHour or MaxCallsPerMin.
func (r *Router) SetCostController(c *CostController) { r.cost = c }

// SetPIIRedactor wires a scrubber. When wired, Chat and AnalyzeLogs sanitize
// all user-provided text before it reaches the active provider.
func (r *Router) SetPIIRedactor(p *PIIRedactor) { r.redactor = p }

// SetProvider sets the active AI provider: "nim", "ollama", "openrouter", or "auto" (auto-failover).
func (r *Router) SetProvider(p string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch p {
	case "nim":
		r.provider = p
		r.useOllama = false
		r.useOpenRouter = false
	case "ollama":
		r.provider = p
		r.useOllama = true
		r.useOpenRouter = false
	case "openrouter":
		r.provider = p
		r.useOllama = false
		r.useOpenRouter = true
	case "auto":
		r.provider = p
	default:
		return // reject unknown providers
	}
}

// UpdateNIMConfig hot-reloads NIM client settings.
func (r *Router) UpdateNIMConfig(apiKey, model, baseURL string) {
	r.nim.UpdateConfig(apiKey, model, baseURL)
}

// UpdateOllamaConfig hot-reloads Ollama client settings.
func (r *Router) UpdateOllamaConfig(url, model string) {
	r.ollama.UpdateConfig(url, model)
}

// UpdateOpenRouterConfig hot-reloads OpenRouter client settings.
func (r *Router) UpdateOpenRouterConfig(apiKey, model, baseURL string) {
	r.openrouter.UpdateConfig(apiKey, model, baseURL)
}

// Chat sends a multi-turn conversation to the active provider. All message
// content is scrubbed via the PII redactor when one is configured.
func (r *Router) Chat(ctx context.Context, systemPrompt string, messages []ChatMessage) (string, error) {
	if r.redactor != nil {
		systemPrompt = r.redactor.Redact(systemPrompt)
		for i := range messages {
			messages[i].Content = r.redactor.Redact(messages[i].Content)
		}
	}
	svc := r.activeService()
	type chatter interface {
		Chat(ctx context.Context, systemPrompt string, messages []ChatMessage) (string, error)
	}
	if c, ok := svc.(chatter); ok {
		return c.Chat(ctx, systemPrompt, messages)
	}
	return "", fmt.Errorf("active provider does not support chat")
}

// ListModels returns available models from the currently configured provider.
func (r *Router) ListModels(ctx context.Context, provider string) ([]string, error) {
	if provider == "ollama" {
		return r.ollama.ListModels(ctx)
	}
	if provider == "openrouter" {
		return r.openrouter.ListModels(ctx)
	}
	// Default to NIM
	if r.nim.cfg.APIKey == "" {
		return nil, fmt.Errorf("NIM API key not configured")
	}
	return r.nim.ListModels(ctx)
}

// NewRouter creates an AI router with failover logic.
func NewRouter(nim *NIMClient, ollama *OllamaClient, openrouter *OpenRouterClient, cfg RouterConfig) *Router {
	if cfg.Threshold == 0 {
		cfg.Threshold = 0.9
	}
	if cfg.Window == 0 {
		cfg.Window = 5 * time.Minute
	}
	r := &Router{
		nim:        nim,
		ollama:     ollama,
		openrouter: openrouter,
		cfg:        cfg,
		stopCh:     make(chan struct{}),
	}
	go r.monitor()
	return r
}

// Stop halts the background monitor goroutine.
func (r *Router) Stop() {
	r.stopOnce.Do(func() { close(r.stopCh) })
}

func (r *Router) monitor() {
	// M-2: a panic in the monitor must not kill the process.
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("ai: router monitor panic recovered: %v", rec)
		}
	}()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			rate := r.nim.SuccessRate()
			r.mu.Lock()
			// M-17: only the "auto" pinning strategy reacts to rate
			// changes; if the operator pinned a provider we leave the
			// selection alone.
			if r.provider == "" || r.provider == "auto" {
				if rate < r.cfg.Threshold && !r.useOllama && !r.useOpenRouter {
					// Snapshot the relevant client fields under lock so we
					// don't read openrouter.cfg unsynchronized.
					openrouterKey := ""
					r.mu.Unlock()
					if r.openrouter != nil {
						openrouterKey = r.openrouter.cfg.APIKey
					}
					r.mu.Lock()
					if r.provider != "" && r.provider != "auto" {
						r.mu.Unlock()
						continue
					}
					if openrouterKey != "" && r.openrouter.SuccessRate() >= r.cfg.Threshold {
						log.Printf("ai: NIM success rate %.1f%% < %.1f%%, switching to OpenRouter", rate*100, r.cfg.Threshold*100)
						r.useOpenRouter = true
						r.useOllama = false
					} else {
						log.Printf("ai: NIM success rate %.1f%% < %.1f%%, switching to Ollama", rate*100, r.cfg.Threshold*100)
						r.useOllama = true
						r.useOpenRouter = false
					}
				} else if rate >= r.cfg.Threshold && (r.useOllama || r.useOpenRouter) {
					log.Printf("ai: NIM success rate %.1f%% recovered, switching back", rate*100)
					r.useOllama = false
					r.useOpenRouter = false
				}
			}
			r.mu.Unlock()
		}
	}
}

func (r *Router) activeService() AIService {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.provider == "openrouter" {
		return r.openrouter
	}
	if r.provider == "nim" {
		return r.nim
	}
	if r.provider == "ollama" {
		return r.ollama
	}
	// auto mode: respect failover state (NIM -> OpenRouter -> Ollama)
	if r.useOpenRouter {
		return r.openrouter
	}
	if r.useOllama {
		return r.ollama
	}
	return r.nim
}

func (r *Router) fallbackService() AIService {
	r.mu.RLock()
	defer r.mu.RUnlock()
	// No fallback in pinned mode
	if r.provider == "nim" || r.provider == "ollama" || r.provider == "openrouter" {
		return nil
	}
	// auto mode: fallback chain is nim -> openrouter -> ollama
	if r.useOllama {
		return r.nim
	}
	return r.ollama
}

// ClassifyRequest enforces cost budget (when configured), tries primary,
// falls back on failure.
func (r *Router) ClassifyRequest(ctx context.Context, features RequestFeatures) (*Classification, error) {
	if r.cost != nil {
		key := features.ClientIP
		if key == "" {
			key = "global"
		}
		if err := r.cost.Allow(ctx, key, 256); err != nil {
			return nil, fmt.Errorf("ai: %w", err)
		}
	}
	if r.redactor != nil {
		features.BodySnippet = r.redactor.Redact(features.BodySnippet)
		features.UserAgent = r.redactor.Redact(features.UserAgent)
	}
	result, err := r.activeService().ClassifyRequest(ctx, features)
	if err != nil {
		fb := r.fallbackService()
		if fb == nil {
			r.recordFailure(err.Error())
			return nil, fmt.Errorf("AI provider failed: %w", err)
		}
		log.Printf("ai: primary classify failed: %v, trying fallback", err)
		result, err = fb.ClassifyRequest(ctx, features)
		if err != nil {
			r.recordFailure(err.Error())
			log.Printf("ai: both providers failed, returning error (fail-closed)")
			return nil, fmt.Errorf("both AI providers failed: %w", err)
		}
	}
	r.recordSuccess()
	return result, nil
}

// DetectAnomaly tries primary, falls back on failure.
func (r *Router) DetectAnomaly(ctx context.Context, stats TrafficStats) (*AnomalyResult, error) {
	result, err := r.activeService().DetectAnomaly(ctx, stats)
	if err != nil {
		fb := r.fallbackService()
		if fb == nil {
			return nil, fmt.Errorf("AI provider failed: %w", err)
		}
		log.Printf("ai: primary anomaly detection failed: %v, trying fallback", err)
		result, err = fb.DetectAnomaly(ctx, stats)
		if err != nil {
			return nil, fmt.Errorf("both providers failed: %w", err)
		}
	}
	return result, nil
}

// GenerateRule tries primary, falls back on failure.
func (r *Router) GenerateRule(ctx context.Context, attacks []AttackPattern) (*GeneratedRule, error) {
	result, err := r.activeService().GenerateRule(ctx, attacks)
	if err != nil {
		fb := r.fallbackService()
		if fb == nil {
			return nil, fmt.Errorf("AI provider failed: %w", err)
		}
		log.Printf("ai: primary rule generation failed: %v, trying fallback", err)
		result, err = fb.GenerateRule(ctx, attacks)
		if err != nil {
			return nil, fmt.Errorf("both providers failed: %w", err)
		}
	}
	return result, nil
}

// AnalyzeLogs tries primary, falls back on failure.
func (r *Router) AnalyzeLogs(ctx context.Context, query string) (*AnalysisResult, error) {
	result, err := r.activeService().AnalyzeLogs(ctx, query)
	if err != nil {
		fb := r.fallbackService()
		if fb == nil {
			return nil, fmt.Errorf("AI provider failed: %w", err)
		}
		log.Printf("ai: primary log analysis failed: %v, trying fallback", err)
		result, err = fb.AnalyzeLogs(ctx, query)
		if err != nil {
			return nil, fmt.Errorf("both providers failed: %w", err)
		}
	}
	return result, nil
}

// Status returns health info for all providers.
type AIStatus struct {
	NIM         ProviderStatus `json:"nim"`
	Ollama      ProviderStatus `json:"ollama"`
	OpenRouter  ProviderStatus `json:"openrouter"`
	Active      string         `json:"active"`
	Degraded    bool           `json:"degraded"`
	LastSuccess time.Time      `json:"last_success,omitempty"`
	LastError   string         `json:"last_error,omitempty"`
}

type ProviderStatus struct {
	Available   bool    `json:"available"`
	SuccessRate float64 `json:"success_rate"`
	Model       string  `json:"model,omitempty"`
	URL         string  `json:"url,omitempty"`
}

// GetStatus returns the current AI system status.
func (r *Router) GetStatus() AIStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()

	active := r.provider
	if active == "" || active == "auto" {
		active = "nim"
		if r.useOpenRouter {
			active = "openrouter"
		} else if r.useOllama {
			active = "ollama"
		}
	}

	nimAvail := r.nim.cfg.APIKey != ""
	ollamaAvail := r.ollama.cfg.URL != ""
	openrouterAvail := r.openrouter.cfg.APIKey != ""

	// Degraded = no provider is healthy. Active is nil in that case.
	nimSR := r.nim.SuccessRate()
	ollamaSR := r.ollama.SuccessRate()
	openrouterSR := r.openrouter.SuccessRate()
	degraded := !nimAvail && !ollamaAvail && !openrouterAvail
	if !degraded {
		// Even with creds configured, if active provider success rate is
		// 0 and there is no failover, treat as degraded.
		switch active {
		case "nim":
			if nimAvail && nimSR == 0 && !r.useOpenRouter && !r.useOllama {
				degraded = true
			}
		case "openrouter":
			if openrouterAvail && openrouterSR == 0 {
				degraded = true
			}
		case "ollama":
			if ollamaAvail && ollamaSR == 0 {
				degraded = true
			}
		}
	}
	lastSuccess, lastErr := r.lastEvent()

	return AIStatus{
		NIM: ProviderStatus{
			Available:   nimAvail,
			SuccessRate: nimSR,
			Model:       r.nim.cfg.Model,
			URL:         r.nim.cfg.BaseURL,
		},
		Ollama: ProviderStatus{
			Available:   ollamaAvail,
			SuccessRate: ollamaSR,
			Model:       r.ollama.cfg.Model,
			URL:         r.ollama.cfg.URL,
		},
		OpenRouter: ProviderStatus{
			Available:   openrouterAvail,
			SuccessRate: openrouterSR,
			Model:       r.openrouter.cfg.Model,
			URL:         r.openrouter.cfg.BaseURL,
		},
		Active:      active,
		Degraded:    degraded,
		LastSuccess: lastSuccess,
		LastError:   lastErr,
	}
}

// lastEvent returns the timestamp + message of the most recent transition.
// Caller must hold r.mu (read or write).
func (r *Router) lastEvent() (time.Time, string) {
	if r.lastErrAt.IsZero() && r.lastSuccessAt.IsZero() {
		return time.Time{}, ""
	}
	if r.lastErrAt.After(r.lastSuccessAt) {
		return r.lastSuccessAt, r.lastErrMsg
	}
	return r.lastSuccessAt, ""
}

// recordSuccess records a successful provider call.
func (r *Router) recordSuccess() {
	r.mu.Lock()
	r.lastSuccessAt = time.Now()
	r.mu.Unlock()
}

// recordFailure records a provider call error.
func (r *Router) recordFailure(msg string) {
	r.mu.Lock()
	r.lastErrAt = time.Now()
	r.lastErrMsg = msg
	r.mu.Unlock()
}
