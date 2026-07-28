package ai

import (
	"testing"
	"time"
)

func TestRouterSuccessRate(t *testing.T) {
	nim := &NIMClient{
		window: 5 * time.Minute,
	}

	// Record some successes and failures
	for i := 0; i < 9; i++ {
		nim.recordSuccess()
	}
	nim.recordFailure()

	rate := nim.SuccessRate()
	if rate != 0.9 {
		t.Errorf("success rate = %f, want 0.9", rate)
	}
}

func TestRouterSuccessRateNoRequests(t *testing.T) {
	nim := &NIMClient{
		window: 5 * time.Minute,
	}
	rate := nim.SuccessRate()
	if rate != 1.0 {
		t.Errorf("success rate (no requests) = %f, want 1.0", rate)
	}
}

func TestRouterGetStatus(t *testing.T) {
	nim := &NIMClient{window: 5 * time.Minute}
	ollama := &OllamaClient{}
	openrouter := &OpenRouterClient{window: 5 * time.Minute}
	router := &Router{
		nim:        nim,
		ollama:     ollama,
		openrouter: openrouter,
		cfg:        RouterConfig{Threshold: 0.9, Window: 5 * time.Minute},
	}

	status := router.GetStatus()
	if status.Active != "nim" {
		t.Errorf("active = %q, want nim", status.Active)
	}
	if status.NIM.SuccessRate != 1.0 {
		t.Errorf("NIM success rate = %f, want 1.0", status.NIM.SuccessRate)
	}
}
