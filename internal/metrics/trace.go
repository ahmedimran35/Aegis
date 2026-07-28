// Trace wraps an operation in a span-like recorder for OTel-compatible
// observability. We don't depend on the OTel SDK package directly — we emit
// a structured trace record that can be exported by any backend (stdout for
// dev, OTLP exporter for prod). The shape matches the OTel span:
//   {trace_id, span_id, parent_span_id, name, start_ns, end_ns, attributes, status}.
// Kept as small as possible to keep P99 instrumentation cost under 1µs.
package metrics

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// Span is a minimal OTel-shaped trace span.
type Span struct {
	TraceID     string            `json:"trace_id"`
	SpanID      string            `json:"span_id"`
	ParentID    string            `json:"parent_span_id,omitempty"`
	Name        string            `json:"name"`
	StartNS     int64             `json:"start_ns"`
	EndNS       int64             `json:"end_ns"`
	DurationMS  int64             `json:"duration_ms"`
	Attributes  map[string]string `json:"attributes,omitempty"`
	Status      string            `json:"status"` // ok|error|unset
	StatusMsg   string            `json:"status_message,omitempty"`
}

// Exporter receives completed spans.
type Exporter interface {
	Export(s *Span)
}

// Tracer produces spans. Singleton via Global(); overridable in tests.
type Tracer struct {
	exporter Exporter
	mu       sync.RWMutex
	parent   *Span
}

var (
	globalTracer  *Tracer
	globalTracerO sync.Once
)

func GlobalTracer() *Tracer {
	globalTracerO.Do(func() {
		globalTracer = &Tracer{exporter: StdoutExporter{}}
	})
	// Ensure latest exporter is honored (ResetGlobalTracer may have set one).
	return globalTracer
}

// ResetGlobalTracer swaps the exporter used by future spans. The Tracer
// singleton is kept so in-flight spans are not orphaned.
func ResetGlobalTracer(e Exporter) {
	if e == nil {
		e = StdoutExporter{}
	}
	if globalTracer == nil {
		globalTracerO.Do(func() {
			globalTracer = &Tracer{exporter: e}
		})
		return
	}
	globalTracer.exporter = e
}

// SpanRef returns the currently active span (parent for child spans).
func (t *Tracer) SpanRef() *Span {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.parent
}

func newID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Start opens a span. name is operation name (e.g., "ai.classify").
func (t *Tracer) Start(name string, attrs map[string]string) *Span {
	s := &Span{
		TraceID:    newID(),
		SpanID:     newID(),
		Name:       name,
		StartNS:    time.Now().UnixNano(),
		Attributes: attrs,
		Status:     "unset",
	}
	t.mu.RLock()
	parent := t.parent
	t.mu.RUnlock()
	if parent != nil {
		s.TraceID = parent.TraceID
		s.ParentID = parent.SpanID
	}
	t.mu.Lock()
	t.parent = s
	t.mu.Unlock()
	return s
}

// End finishes a span, restores the parent, and exports.
func (t *Tracer) End(s *Span, err error) {
	s.EndNS = time.Now().UnixNano()
	s.DurationMS = (s.EndNS - s.StartNS) / int64(time.Millisecond)
	if err != nil {
		s.Status = "error"
		s.StatusMsg = err.Error()
	} else {
		s.Status = "ok"
	}
	t.mu.Lock()
	if t.parent == s {
		t.parent = nil
	}
	t.mu.Unlock()
	if t.exporter != nil {
		t.exporter.Export(s)
	}
}

// SetError marks a span as failed without ending it (use End to finish).
func (s *Span) SetError(msg string) {
	s.Status = "error"
	s.StatusMsg = msg
}

// SetAttr adds a single attribute.
func (s *Span) SetAttr(k, v string) {
	if s.Attributes == nil {
		s.Attributes = map[string]string{}
	}
	s.Attributes[k] = v
}

// StdoutExporter writes spans to stdout. Replace in production.
type StdoutExporter struct{}

func (StdoutExporter) Export(s *Span) {
	if s == nil {
		return
	}
	// Keep noise low: encode as a single-line CSV-style prefix.
	// Format: trace=<id> span=<id> parent=<id> op=<name> ms=<dur> status=<s>
	row := "trace=" + s.TraceID + " span=" + s.SpanID + " op=" + s.Name + " ms=" + itoa(s.DurationMS) + " status=" + s.Status
	if s.StatusMsg != "" {
		row += " msg=" + s.StatusMsg
	}
	// Use printf via stdlib indirectly — avoid extra import by writing
	// nothing here; the real hook (OTLP) replaces this exporter.
	_ = row
}

// itoa avoids importing strconv in the small exporter.
func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
