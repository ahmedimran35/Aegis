package metrics

import (
	"errors"
	"testing"
)

func TestTracerStartEnd(t *testing.T) {
	type captured struct{ last *Span }
	cap := &exporterStub{}
	ResetGlobalTracer(cap)
	defer ResetGlobalTracer(StdoutExporter{})

	tr := GlobalTracer()
	s := tr.Start("test.op", map[string]string{"key": "v"})
	if s.SpanID == "" {
		t.Fatal("missing span id")
	}
	tr.End(s, nil)
	if cap.last != s {
		t.Fatalf("exporter not called with span")
	}
	if s.Status != "ok" {
		t.Fatalf("status = %s, want ok", s.Status)
	}
}

func TestTracerEndError(t *testing.T) {
	cap := &exporterStub{}
	ResetGlobalTracer(cap)
	defer ResetGlobalTracer(StdoutExporter{})

	tr := GlobalTracer()
	s := tr.Start("test.fail", nil)
	tr.End(s, errors.New("boom"))
	if s.Status != "error" {
		t.Fatalf("status = %s, want error", s.Status)
	}
	if s.StatusMsg != "boom" {
		t.Fatalf("msg = %q", s.StatusMsg)
	}
}

func TestTracerNested(t *testing.T) {
	cap := &exporterStub{}
	ResetGlobalTracer(cap)
	defer ResetGlobalTracer(StdoutExporter{})

	tr := GlobalTracer()
	parent := tr.Start("outer", nil)
	defer tr.End(parent, nil)
	if parent.SpanID == "" || parent.TraceID == "" {
		t.Fatal("parent ids missing")
	}
	child := tr.Start("inner", nil)
	if child.TraceID != parent.TraceID {
		t.Errorf("child trace = %s, want %s", child.TraceID, parent.TraceID)
	}
	if child.ParentID != parent.SpanID {
		t.Errorf("child parent = %s, want %s", child.ParentID, parent.SpanID)
	}
	tr.End(child, nil)
}

type exporterStub struct{ last *Span }

func (e *exporterStub) Export(s *Span) { e.last = s }
