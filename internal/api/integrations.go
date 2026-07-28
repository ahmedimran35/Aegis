package api

import (
	"net/http"

	wafmw "github.com/user/waf/internal/middleware"
)

type IntegrationStatsHandler struct {
	slowDoS       *wafmw.SlowDoSDetector
	behavioralBot *wafmw.BehavioralBotScorer
	bola          *wafmw.BOLADetector
	credStuffing  *wafmw.CredentialStuffingDetector
	shadowAPI     *wafmw.ShadowAPIDiscovery
	policyTuner   *wafmw.PolicyTuner
	cspNonce      *wafmw.CSPNonceMiddleware
}

func NewIntegrationStatsHandler(slowDoS *wafmw.SlowDoSDetector, behavioralBot *wafmw.BehavioralBotScorer,
	bola *wafmw.BOLADetector, credStuffing *wafmw.CredentialStuffingDetector,
	shadowAPI *wafmw.ShadowAPIDiscovery, policyTuner *wafmw.PolicyTuner,
	cspNonce *wafmw.CSPNonceMiddleware) *IntegrationStatsHandler {
	return &IntegrationStatsHandler{
		slowDoS:       slowDoS,
		behavioralBot: behavioralBot,
		bola:          bola,
		credStuffing:  credStuffing,
		shadowAPI:     shadowAPI,
		policyTuner:   policyTuner,
		cspNonce:      cspNonce,
	}
}

func (h *IntegrationStatsHandler) AllStats(w http.ResponseWriter, r *http.Request) {
	stats := make(map[string]interface{})
	if h.slowDoS != nil {
		stats["slow_dos"] = h.slowDoS.Stats()
	}
	if h.behavioralBot != nil {
		stats["behavioral_bot"] = h.behavioralBot.Stats()
	}
	if h.bola != nil {
		stats["bola"] = h.bola.Stats()
	}
	if h.credStuffing != nil {
		stats["credential_stuffing"] = h.credStuffing.Stats()
	}
	if h.shadowAPI != nil {
		stats["shadow_api"] = h.shadowAPI.Stats()
	}
	if h.policyTuner != nil {
		stats["policy_tuner"] = h.policyTuner.Stats()
	}
	if h.cspNonce != nil {
		stats["csp_nonce"] = h.cspNonce.Stats()
	}
	RespondJSON(w, http.StatusOK, stats)
}
