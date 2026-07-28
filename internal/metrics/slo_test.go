package metrics

import (
	"testing"
	"time"
)

func TestSLOBudgetRecord(t *testing.T) {
	b := NewSLOBudget("t", 0.99, time.Minute)
	// all successes → burn = 0
	for i := 0; i < 100; i++ {
		b.Record(true)
	}
	if b.Burn() != 0 {
		t.Errorf("all-success burn = %f, want 0", b.Burn())
	}
	// 50/50 → observed = 0.5, target = 0.99 → burn ~= 0.494
	for i := 0; i < 100; i++ {
		b.Record(false)
	}
	if br := b.Burn(); br < 0.4 || br > 0.6 {
		t.Errorf("50/50 burn = %f, want ~0.49", br)
	}
}

func TestSLOBudgetRemainingClamped(t *testing.T) {
	b := NewSLOBudget("t", 0.99, time.Minute)
	for i := 0; i < 100; i++ {
		b.Record(false)
	}
	rem := b.BudgetRemaining()
	if rem < 0 {
		t.Errorf("remaining = %f, want >= 0", rem)
	}
	if rem > 1 {
		t.Errorf("remaining = %f, want <= 1", rem)
	}
}

func TestGlobalSnapshot(t *testing.T) {
	ResetGlobal()
	defer ResetGlobal()
	c := Global()
	c.RecordClassification(true, 50*time.Millisecond)
	c.RecordHTTP(200)
	c.RecordHTTP(503)
	snap := c.Snapshot()
	if _, ok := snap["classification_budget_remaining"]; !ok {
		t.Fatalf("missing classification_budget_remaining in snapshot")
	}
}

func TestGlobalClassificationLatencyBudget(t *testing.T) {
	ResetGlobal()
	defer ResetGlobal()
	c := Global()
	// 5 within budget, 1 over — burn should be tiny
	for i := 0; i < 5; i++ {
		c.RecordClassification(true, 100*time.Millisecond)
	}
	c.RecordClassification(true, 1*time.Second)
	if burn := c.latency.Burn(); burn < 0 || burn > 1 {
		t.Errorf("latency burn = %f", burn)
	}
}
