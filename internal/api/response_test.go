package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRespondJSON(t *testing.T) {
	w := httptest.NewRecorder()
	RespondJSON(w, http.StatusOK, map[string]string{"key": "value"})

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var resp SuccessResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Success {
		t.Error("expected success=true")
	}
}

func TestRespondError(t *testing.T) {
	w := httptest.NewRecorder()
	RespondError(w, http.StatusNotFound, "NOT_FOUND", "resource not found")

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}

	var resp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Success {
		t.Error("expected success=false")
	}
	if resp.Error.Code != "NOT_FOUND" {
		t.Errorf("error code = %q, want NOT_FOUND", resp.Error.Code)
	}
}

func TestRespondJSONWithMeta(t *testing.T) {
	w := httptest.NewRecorder()
	RespondJSONWithMeta(w, http.StatusOK, []int{1, 2, 3}, &Meta{
		Page: 1, PerPage: 50, Total: 100,
	})

	var resp SuccessResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Meta == nil {
		t.Fatal("expected meta to be set")
	}
	if resp.Meta.Total != 100 {
		t.Errorf("meta.Total = %d, want 100", resp.Meta.Total)
	}
}
