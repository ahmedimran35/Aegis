package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	wafmw "github.com/user/waf/internal/middleware"
)

func TestIntegrationStatsIncludesPolicyAndCSP(t *testing.T) {
	handler := NewIntegrationStatsHandler(nil, nil, nil, nil, nil, wafmw.NewPolicyTuner(wafmw.DefaultPolicyTunerConfig(), nil), wafmw.NewCSPNonceMiddleware(wafmw.DefaultCSPNonceConfig()))
	req := httptest.NewRequest("GET", "/api/v1/integrations/stats", nil)
	w := httptest.NewRecorder()

	handler.AllStats(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	var resp SuccessResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	body, ok := resp.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("response data type = %T", resp.Data)
	}
	if _, ok := body["policy_tuner"]; !ok {
		t.Error("policy_tuner stats missing")
	}
	if _, ok := body["csp_nonce"]; !ok {
		t.Error("csp_nonce stats missing")
	}
}
