package ai

import (
	"testing"
)

func TestRouterGetStatus_DegradedNoProviders(t *testing.T) {
	r := &Router{
		nim:        &NIMClient{cfg: NIMConfig{APIKey: "", BaseURL: ""}},
		ollama:     &OllamaClient{cfg: OllamaConfig{URL: ""}},
		openrouter: &OpenRouterClient{cfg: OpenRouterConfig{APIKey: ""}},
		provider:   "auto",
	}
	status := r.GetStatus()
	if !status.Degraded {
		t.Errorf("expected Degraded=true when no providers configured")
	}
	if status.Active == "" {
		t.Errorf("expected non-empty Active for visibility")
	}
}

func TestRouterGetStatus_LastEvent(t *testing.T) {
	r := &Router{
		nim:        &NIMClient{cfg: NIMConfig{APIKey: "key", BaseURL: "url"}},
		ollama:     &OllamaClient{cfg: OllamaConfig{URL: ""}},
		openrouter: &OpenRouterClient{cfg: OpenRouterConfig{APIKey: ""}},
		provider:   "nim",
	}
	r.recordSuccess()
	status := r.GetStatus()
	if status.LastSuccess.IsZero() {
		t.Errorf("expected LastSuccess set after recordSuccess")
	}
	if status.LastError != "" {
		t.Errorf("expected LastError empty after success, got %q", status.LastError)
	}
}

func TestRouterGetStatus_LastError(t *testing.T) {
	r := &Router{
		nim:        &NIMClient{cfg: NIMConfig{APIKey: "key", BaseURL: "url"}},
		ollama:     &OllamaClient{cfg: OllamaConfig{URL: ""}},
		openrouter: &OpenRouterClient{cfg: OpenRouterConfig{APIKey: ""}},
		provider:   "nim",
	}
	r.recordFailure("boom")
	status := r.GetStatus()
	if status.LastError != "boom" {
		t.Errorf("expected LastError=boom, got %q", status.LastError)
	}
}