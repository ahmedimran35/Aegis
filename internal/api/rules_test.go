package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

func setupRuleRouter(handler *RuleHandler) http.Handler {
	r := chi.NewRouter()
	r.Route("/api/v1/rules", func(r chi.Router) {
		r.Get("/", handler.List)
		r.Post("/", handler.Create)
		r.Route("/{id}", func(r chi.Router) {
			r.Get("/", handler.Get)
			r.Put("/", handler.Update)
			r.Delete("/", handler.Delete)
			r.Put("/toggle", handler.Toggle)
			r.Get("/stats", handler.Stats)
		})
	})
	return r
}

func TestRuleListNoDB(t *testing.T) {
	// Test that List returns an error when no DB is available
	handler := &RuleHandler{pool: nil}
	router := setupRuleRouter(handler)

	req := httptest.NewRequest("GET", "/api/v1/rules", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should return 500 since no DB pool is set
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
}

func TestCreateValidation(t *testing.T) {
	handler := &RuleHandler{pool: nil}
	router := setupRuleRouter(handler)

	// Missing fields
	body := bytes.NewBufferString(`{"name":"test"}`)
	req := httptest.NewRequest("POST", "/api/v1/rules", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	var resp ErrorResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Error.Code != "MISSING_FIELDS" {
		t.Errorf("error code = %q, want MISSING_FIELDS", resp.Error.Code)
	}
}

func TestCreateInvalidJSON(t *testing.T) {
	handler := &RuleHandler{pool: nil}
	router := setupRuleRouter(handler)

	body := bytes.NewBufferString(`not json`)
	req := httptest.NewRequest("POST", "/api/v1/rules", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestGetInvalidID(t *testing.T) {
	handler := &RuleHandler{pool: nil}
	router := setupRuleRouter(handler)

	req := httptest.NewRequest("GET", "/api/v1/rules/abc", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}
