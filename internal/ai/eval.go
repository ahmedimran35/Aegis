package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// EvalCase is a single labeled request for offline evaluation.
type EvalCase struct {
	Name           string  `json:"name"`
	Method         string  `json:"method"`
	Path           string  `json:"path"`
	Body           string  `json:"body,omitempty"`
	UserAgent      string  `json:"user_agent"`
	ClientIP       string  `json:"client_ip"`
	ExpectedLabel  string  `json:"expected_label"` // benign | suspicious | malicious
	ExpectedBlock  bool    `json:"expected_block"`
}

// EvalResult captures a single prediction vs. ground truth.
type EvalResult struct {
	Case       EvalCase `json:"case"`
	Predicted  string   `json:"predicted"`
	Score      float64  `json:"score"`
	Blocked    bool     `json:"blocked"`
	Correct    bool     `json:"correct"`
	FalsePos   bool     `json:"false_positive"`
	FalseNeg   bool     `json:"false_negative"`
	LatencyMS  int64    `json:"latency_ms"`
	Err        string   `json:"error,omitempty"`
}

// EvalReport is the aggregate report for a corpus run.
type EvalReport struct {
	Total         int     `json:"total"`
	Correct       int     `json:"correct"`
	FalsePos      int     `json:"false_positives"`
	FalseNeg      int     `json:"false_negatives"`
	Errors        int     `json:"errors"`
	Accuracy      float64 `json:"accuracy"`
	Precision     float64 `json:"precision"`
	Recall        float64 `json:"recall"`
	F1            float64 `json:"f1"`
	P50LatencyMS  int64   `json:"p50_latency_ms"`
	P95LatencyMS  int64   `json:"p95_latency_ms"`
	AvgScore      float64 `json:"avg_score"`
	StartedAt     string  `json:"started_at"`
	FinishedAt    string  `json:"finished_at"`
}

// EvalHarness runs an EvalCase corpus against the router in a deterministic,
// rate-limited loop and produces an EvalReport.
type EvalHarness struct {
	router   *Router
	report   EvalReport
	mu       sync.Mutex
}

// NewEvalHarness wires the router. Router may be nil — in that case only
// offline validation runs (no predictions).
func NewEvalHarness(r *Router) *EvalHarness {
	return &EvalHarness{router: r}
}

// LoadCorpus reads a JSON array of EvalCase from disk.
func LoadCorpus(path string) ([]EvalCase, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read corpus: %w", err)
	}
	var cases []EvalCase
	if err := json.Unmarshal(b, &cases); err != nil {
		return nil, fmt.Errorf("parse corpus: %w", err)
	}
	if len(cases) == 0 {
		return nil, fmt.Errorf("corpus is empty")
	}
	return cases, nil
}

// Run evaluates each case sequentially with a 5s per-call budget. Caller may
// invoke from a goroutine; results stream into a channel.
func (h *EvalHarness) Run(ctx context.Context, cases []EvalCase) <-chan EvalResult {
	out := make(chan EvalResult, 32)
	h.report = EvalReport{StartedAt: time.Now().UTC().Format(time.RFC3339)}

	// H-15: helper that performs a non-blocking send. If the caller is no
	// longer reading the channel (e.g. HTTP client disconnected mid-stream)
	// we drop the result and increment dropped so the harness does not
	// block forever in a tight loop and starve the rest of the engine.
	var dropped atomic.Int64
	trySend := func(r EvalResult) {
		select {
		case out <- r:
		default:
			dropped.Add(1)
		}
	}

	go func() {
		defer close(out)
		var (
			tp, fp, fn, correct, errs int64
			totalScore                atomic.Uint64
			latencies                 = make([]int64, 0, len(cases))
		)

		for i, c := range cases {
			select {
			case <-ctx.Done():
				trySend(EvalResult{Err: "ctx cancelled"})
				goto done
			default:
			}

			res := h.evalOne(ctx, c)
			trySend(res)

			correct += boolToInt(res.Correct)
			fp += boolToInt(res.FalsePos)
			fn += boolToInt(res.FalseNeg)
			// P-FIX: track TP as "blocked AND expected_block", not as total
			// count. The previous `tp++` incremented for every case (including
			// false negatives and benign cases), which broke the precision
			// formula downstream.
			if res.Blocked && c.ExpectedBlock {
				tp++
			}
			if res.Err != "" {
				errs++
			} else {
				totalScore.Add(uint64(res.Score * 10000))
			}
			latencies = append(latencies, res.LatencyMS)

			_ = i
		}
		done:
		if d := dropped.Load(); d > 0 {
			log.Printf("eval: %d result(s) dropped (caller not reading channel)", d)
		}
		// total = all evaluated cases = TP + FP + FN + TN. We compute it
		// from the per-case counts: total = correct + fp + fn (correct
		// includes both TP and TN; fp is cases where blocked but not
		// expected; fn is cases where not blocked but expected).
		total := int(correct + fp + fn)
		h.finalize(total, int(correct), int(fp), int(fn), int(errs), int(tp), totalScore.Load(), latencies)
	}()
	return out
}

func (h *EvalHarness) evalOne(ctx context.Context, c EvalCase) EvalResult {
	if h.router == nil {
		return EvalResult{Case: c, Err: "no router configured"}
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	feats := RequestFeatures{
		Method:      c.Method,
		Path:        c.Path,
		BodyHash:    hashBody(c.Body),
		BodySnippet: truncate(c.Body, 256),
		UserAgent:   c.UserAgent,
		ClientIP:    c.ClientIP,
	}

	start := time.Now()
	cls, err := h.router.ClassifyRequest(cctx, feats)
	latency := time.Since(start).Milliseconds()

	if err != nil {
		return EvalResult{Case: c, Err: err.Error(), LatencyMS: latency}
	}

	blocked := cls.Classification == "malicious" || cls.Score >= 0.85
	res := EvalResult{
		Case:      c,
		Predicted: cls.Classification,
		Score:     cls.Score,
		Blocked:   blocked,
		Correct:   blocked == c.ExpectedBlock,
		FalsePos:  blocked && !c.ExpectedBlock,
		FalseNeg:  !blocked && c.ExpectedBlock,
		LatencyMS: latency,
	}
	return res
}

func (h *EvalHarness) finalize(total, correct, fp, fn, errs int, tpCount int, scoreSum uint64, lats []int64) {
	rep := EvalReport{
		Total:      total,
		Correct:    correct,
		FalsePos:   fp,
		FalseNeg:   fn,
		Errors:     errs,
		StartedAt:  h.report.StartedAt,
		FinishedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if total > 0 {
		rep.Accuracy = float64(correct) / float64(total)
	}
	// Precision/recall: P-FIX — the previous formula treated `correct` as a
	// TP aggregate and subtracted `fn` to get TP, but `correct` includes both
	// true positives AND true negatives. The correct formulation uses a
	// proper TP accumulator (tracked in the Run loop):
	//   TP = cases where blocked && expected_block
	//   FP = cases where blocked && !expected_block
	//   FN = cases where !blocked && expected_block
	//   Precision = TP / (TP + FP)
	//   Recall    = TP / (TP + FN)
	//   F1        = 2*P*R / (P+R)
	if (tpCount + fp) > 0 {
		rep.Precision = float64(tpCount) / float64(tpCount+fp)
	}
	if (tpCount + fn) > 0 {
		rep.Recall = float64(tpCount) / float64(tpCount+fn)
	}
	if rep.Precision+rep.Recall > 0 {
		rep.F1 = 2 * (rep.Precision * rep.Recall) / (rep.Precision + rep.Recall)
	}
	rep.P50LatencyMS = percentile(lats, 50)
	rep.P95LatencyMS = percentile(lats, 95)
	if total > errs {
		rep.AvgScore = float64(scoreSum) / float64(total-errs) / 10000
	}

	h.mu.Lock()
	h.report = rep
	h.mu.Unlock()
	log.Printf("eval: report total=%d correct=%d fp=%d fn=%d errs=%d acc=%.3f p50=%dms p95=%dms",
		rep.Total, rep.Correct, rep.FalsePos, rep.FalseNeg, rep.Errors, rep.Accuracy, rep.P50LatencyMS, rep.P95LatencyMS)
}

// Report returns the latest completed EvalReport.
func (h *EvalHarness) Report() EvalReport {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.report
}

// SaveReport writes the EvalReport as JSON to path.
func (h *EvalHarness) SaveReport(path string) error {
	rep := h.Report()
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func boolToInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

func hashBody(b string) string {
	if b == "" {
		return ""
	}
	// Cheap non-crypto hash; sufficient for dedupe labeling.
	var h uint64 = 1469598103934665603
	for i := 0; i < len(b); i++ {
		h ^= uint64(b[i])
		h *= 1099511628211
	}
	return fmt.Sprintf("%016x", h)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func percentile(lats []int64, p int) int64 {
	if len(lats) == 0 {
		return 0
	}
	// copy + sort — small slice per run, OK
	c := make([]int64, len(lats))
	copy(c, lats)
	// insertion sort, faster than sort for small N
	for i := 1; i < len(c); i++ {
		v := c[i]
		j := i
		for j > 0 && c[j-1] > v {
			c[j] = c[j-1]
			j--
		}
		c[j] = v
	}
	idx := (p * (len(c) - 1)) / 100
	return c[idx]
}
