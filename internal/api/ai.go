package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/user/waf/internal/ai"
)

// AIHandler handles AI-related API endpoints.
type AIHandler struct {
	router *ai.Router
	pool   *pgxpool.Pool
}

// NewAIHandler creates a new AI handler.
func NewAIHandler(router *ai.Router, pool *pgxpool.Pool) *AIHandler {
	return &AIHandler{router: router, pool: pool}
}

// Status handles GET /api/v1/ai/status
func (h *AIHandler) Status(w http.ResponseWriter, r *http.Request) {
	status := h.router.GetStatus()
	RespondJSON(w, http.StatusOK, status)
}

// analyzeRequest is the payload for the analyze endpoint.
type analyzeRequest struct {
	Query string `json:"query"`
}

// Analyze handles POST /api/v1/ai/analyze
func (h *AIHandler) Analyze(w http.ResponseWriter, r *http.Request) {
	var req analyzeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Query == "" {
		RespondError(w, http.StatusBadRequest, "INVALID_REQUEST", "query is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 35*time.Second)
	defer cancel()

	result, err := h.router.AnalyzeLogs(ctx, req.Query)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "AI_ERROR", safeError(err, "AI"))
		return
	}

	RespondJSON(w, http.StatusOK, result)
}

// generateRuleRequest is the payload for rule generation.
type generateRuleRequest struct {
	Examples []string `json:"examples"`
	Category string   `json:"category"`
	Count    int      `json:"count"`
}

// GenerateRule handles POST /api/v1/ai/generate-rule
func (h *AIHandler) GenerateRule(w http.ResponseWriter, r *http.Request) {
	var req generateRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid request body")
		return
	}

	if len(req.Examples) == 0 {
		RespondError(w, http.StatusBadRequest, "MISSING_FIELDS", "examples are required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 35*time.Second)
	defer cancel()

	result, err := h.router.GenerateRule(ctx, []ai.AttackPattern{
		{Examples: req.Examples, Category: req.Category, Count: req.Count},
	})
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "AI_ERROR", safeError(err, "AI"))
		return
	}

	RespondJSON(w, http.StatusOK, result)
}

// chatRequest is the payload for the chat endpoint.
type chatRequest struct {
	Message string `json:"message"`
}

// Chat handles POST /api/v1/ai/chat — natural language chat with full Aegis data context.
func (h *AIHandler) Chat(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Message  string          `json:"message"`
		History  []ai.ChatMessage `json:"history,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Message == "" {
		RespondError(w, http.StatusBadRequest, "INVALID_REQUEST", "message is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()

	// Gather comprehensive Aegis context
	var totalReqs, blockedReqs, uniqueIPs, totalRules, totalAnomalies int
	var blockRate float64
	var topIPs, topEndpoints, recentThreats, recentBlocked, ruleSummary, anomalySummary string
	var topCountries, topUserAgents string

	if h.pool != nil {
		if err := h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM request_logs WHERE timestamp >= CURRENT_DATE`).Scan(&totalReqs); err != nil {
			log.Printf("ai status: scan: %v", err)
		}
		if err := h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM request_logs WHERE timestamp >= CURRENT_DATE AND action = 'blocked'`).Scan(&blockedReqs); err != nil {
			log.Printf("ai status: scan: %v", err)
		}
		if err := h.pool.QueryRow(ctx, `SELECT COUNT(DISTINCT client_ip) FROM request_logs WHERE timestamp >= CURRENT_DATE`).Scan(&uniqueIPs); err != nil {
			log.Printf("ai status: scan: %v", err)
		}
		if totalReqs > 0 {
			blockRate = float64(blockedReqs) / float64(totalReqs) * 100
		}

		// Active rules count
		if err := h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM rules WHERE enabled = true`).Scan(&totalRules); err != nil {
			log.Printf("ai status: scan: %v", err)
		}

		// Unresolved anomalies
		if err := h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM anomalies WHERE resolved = false`).Scan(&totalAnomalies); err != nil {
			log.Printf("ai status: scan: %v", err)
		}

		// Top attacking IPs with threat scores
		rows, err := h.pool.Query(ctx, `SELECT client_ip::text, COUNT(*) as cnt, COALESCE(MAX(threat_score), 0) as max_score
			FROM request_logs WHERE timestamp >= CURRENT_DATE
			GROUP BY client_ip ORDER BY cnt DESC LIMIT 8`)
		if err == nil {
			defer rows.Close()
			var parts []string
			for rows.Next() {
				var ip string
				var cnt int
				var maxScore float64
				rows.Scan(&ip, &cnt, &maxScore)
				parts = append(parts, fmt.Sprintf("%s (%d reqs, threat: %.2f)", ip, cnt, maxScore))
			}
			if len(parts) > 0 {
				topIPs = strings.Join(parts, "\n  ")
			}
		}

		// Top targeted endpoints
		rows, err = h.pool.Query(ctx, `SELECT path, COUNT(*) as cnt,
			COUNT(*) FILTER (WHERE action = 'blocked') as blocked
			FROM request_logs WHERE timestamp >= CURRENT_DATE
			GROUP BY path ORDER BY cnt DESC LIMIT 8`)
		if err == nil {
			defer rows.Close()
			var parts []string
			for rows.Next() {
				var path string
				var cnt, blocked int
				rows.Scan(&path, &cnt, &blocked)
				parts = append(parts, fmt.Sprintf("%s (%d total, %d blocked)", path, cnt, blocked))
			}
			if len(parts) > 0 {
				topEndpoints = strings.Join(parts, "\n  ")
			}
		}

		// Recent threat events
		rows, err = h.pool.Query(ctx, `SELECT client_ip::text, method, path, ai_classification, COALESCE(threat_score, 0)
			FROM request_logs WHERE timestamp >= CURRENT_DATE AND ai_classification NOT IN ('benign', 'unknown')
			ORDER BY timestamp DESC LIMIT 10`)
		if err == nil {
			defer rows.Close()
			var parts []string
			for rows.Next() {
				var ip, method, path, class string
				var score float64
				rows.Scan(&ip, &method, &path, &class, &score)
				parts = append(parts, fmt.Sprintf("%s %s from %s [class: %s, score: %.2f]", method, path, ip, class, score))
			}
			if len(parts) > 0 {
				recentThreats = strings.Join(parts, "\n  ")
			}
		}

		// Recently blocked requests with reasons
		rows, err = h.pool.Query(ctx, `SELECT client_ip::text, method, path, action, COALESCE(rule_name, 'unknown')
			FROM request_logs WHERE timestamp >= CURRENT_DATE AND action = 'blocked'
			ORDER BY timestamp DESC LIMIT 5`)
		if err == nil {
			defer rows.Close()
			var parts []string
			for rows.Next() {
				var ip, method, path, action, rule string
				rows.Scan(&ip, &method, &path, &action, &rule)
				parts = append(parts, fmt.Sprintf("%s %s from %s [rule: %s]", method, path, ip, rule))
			}
			if len(parts) > 0 {
				recentBlocked = strings.Join(parts, "\n  ")
			}
		}

		// Top countries
		rows, err = h.pool.Query(ctx, `SELECT COALESCE(country, 'unknown') as c, COUNT(*) as cnt
			FROM request_logs WHERE timestamp >= CURRENT_DATE
			GROUP BY c ORDER BY cnt DESC LIMIT 5`)
		if err == nil {
			defer rows.Close()
			var parts []string
			for rows.Next() {
				var country string
				var cnt int
				rows.Scan(&country, &cnt)
				parts = append(parts, fmt.Sprintf("%s (%d)", country, cnt))
			}
			if len(parts) > 0 {
				topCountries = strings.Join(parts, ", ")
			}
		}

		// Top user agents
		rows, err = h.pool.Query(ctx, `SELECT COALESCE(user_agent, 'unknown') as ua, COUNT(*) as cnt
			FROM request_logs WHERE timestamp >= CURRENT_DATE
			GROUP BY ua ORDER BY cnt DESC LIMIT 5`)
		if err == nil {
			defer rows.Close()
			var parts []string
			for rows.Next() {
				var ua string
				var cnt int
				rows.Scan(&ua, &cnt)
				// Truncate long UAs
				if len(ua) > 60 {
					ua = ua[:60] + "..."
				}
				parts = append(parts, fmt.Sprintf("%s (%d)", ua, cnt))
			}
			if len(parts) > 0 {
				topUserAgents = strings.Join(parts, "\n  ")
			}
		}

		// Rule categories summary
		rows, err = h.pool.Query(ctx, `SELECT severity, COUNT(*) as cnt FROM rules WHERE enabled = true GROUP BY severity ORDER BY cnt DESC`)
		if err == nil {
			defer rows.Close()
			var parts []string
			for rows.Next() {
				var sev string
				var cnt int
				rows.Scan(&sev, &cnt)
				parts = append(parts, fmt.Sprintf("%s: %d", sev, cnt))
			}
			if len(parts) > 0 {
				ruleSummary = strings.Join(parts, ", ")
			}
		}

		// Recent anomalies
		rows, err = h.pool.Query(ctx, `SELECT type, severity, description, resolved
			FROM anomalies ORDER BY created_at DESC LIMIT 5`)
		if err == nil {
			defer rows.Close()
			var parts []string
			for rows.Next() {
				var typ, sev, desc string
				var resolved bool
				rows.Scan(&typ, &sev, &desc, &resolved)
				status := "OPEN"
				if resolved {
					status = "resolved"
				}
				parts = append(parts, fmt.Sprintf("[%s] %s: %s (%s)", sev, typ, desc, status))
			}
			if len(parts) > 0 {
				anomalySummary = strings.Join(parts, "\n  ")
			}
		}
	}

	systemPrompt := `You are the Aegis Security Assistant — a senior cybersecurity AI embedded in a Web Application Firewall dashboard. You have real-time access to ALL Aegis data: traffic logs, threat intelligence, rules engine, anomaly detection, sessions, GeoIP data, bot detection, rate limiting, DDoS protection, SIEM integration, and security events.

IDENTITY:
You are the authoritative security expert for this Aegis deployment. You know this system inside-out. You speak with confidence and precision. You never hedge with "I think" or "it seems" — you analyze the data and deliver clear verdicts.

CAPABILITIES:
- Deep traffic analysis: identify attack campaigns, correlate IPs, detect slow-burn reconnaissance
- Threat intelligence: explain any attack vector (SQLi, XSS, RCE, SSRF, path traversal, etc.) and its real-world impact
- Rule management: recommend, explain, and help create Aegis rules with specific patterns
- Incident response: step-by-step investigation playbooks for active threats
- Performance analysis: throughput, latency, block rates, false positive rates
- Security posture assessment: identify gaps, recommend hardening measures
- GeoIP & bot analysis: geographic threat mapping, bot vs human traffic patterns
- Explain every Aegis feature and how to use the dashboard effectively
- General cybersecurity expertise: OWASP Top 10, zero-day patterns, CVE context

BEHAVIOR:
- Proactive: if you see concerning data patterns (spike in blocks, new threat actor, anomaly), flag it immediately without being asked
- Actionable: every response includes concrete next steps — specific rules to add, IPs to block, configs to change
- Precise: use exact numbers from the live data. Never fabricate statistics
- Structured: use headers, bullet points, and code blocks for clarity
- Confident: you are the security expert. Give recommendations, not suggestions
- Contextual: reference previous messages in the conversation to build on prior analysis
- Threat-aware: when discussing attacks, always assess severity and urgency

IMPORTANT:
- You have LIVE access to the Aegis database. Use the actual numbers below — do not make up data
- If data shows "none", state clearly there's no data yet and suggest what to look for
- Always reference specific IPs, endpoints, rules, and timestamps from the live data when relevant
- When recommending actions, be specific: exact IP to block, exact rule pattern, exact setting to change
- Format responses in clean markdown. Do NOT wrap in JSON — respond with plain text directly`

	// Build context block
	dataContext := fmt.Sprintf(`=== LIVE AEGIS DATA (as of now) ===

SYSTEM CAPABILITIES:
- AI-powered request classification (NIM + Ollama)
- Anomaly detection with traffic pattern analysis
- Rule engine: regex, pattern, severity-based rules with auto-generation
- GeoIP blocking: country-based filtering
- Bot detection: user-agent analysis, headless browser fingerprinting
- Rate limiting: per-IP, per-endpoint configurable limits
- DDoS protection: threshold-based blocking with auto-escalation
- Honeypot traps: decoy endpoints to detect scanners
- SIEM integration: syslog forwarding for security events
- JA3 TLS fingerprinting: detect malicious TLS clients
- Request body inspection: JSON/XML schema validation
- SSRF protection: block internal network access attempts
- Session tracking: per-IP threat scoring and behavior profiling
- WebSocket inspection: real-time traffic monitoring

TRAFFIC OVERVIEW:
- Total requests today: %d
- Blocked requests: %d (%.1f%%)
- Unique client IPs: %d
- Active Aegis rules: %d
- Unresolved anomalies: %d

RULES BY SEVERITY: %s

TOP ATTACKING IPs:
  %s

TOP TARGETED ENDPOINTS:
  %s

RECENT THREATS:
  %s

RECENTLY BLOCKED:
  %s

TOP COUNTRIES: %s

TOP USER AGENTS:
  %s

OPEN ANOMALIES:
  %s
=== END AEGIS DATA ===`,
		totalReqs, blockedReqs, blockRate, uniqueIPs, totalRules, totalAnomalies,
		noneStr(ruleSummary),
		noneStr(topIPs),
		noneStr(topEndpoints),
		noneStr(recentThreats),
		noneStr(recentBlocked),
		noneStr(topCountries),
		noneStr(topUserAgents),
		noneStr(anomalySummary))

	// Build conversation messages with history
	var messages []ai.ChatMessage

	// Add prior conversation history — only user/assistant roles, max 20 messages
	history := req.History
	if len(history) > 20 {
		history = history[len(history)-20:]
	}
	for _, m := range history {
		if m.Role != "user" && m.Role != "assistant" {
			continue
		}
		content := m.Content
		if len(content) > 2000 {
			content = content[:2000]
		}
		messages = append(messages, ai.ChatMessage{Role: m.Role, Content: content})
	}

	// Current message with live data context injected
	messages = append(messages, ai.ChatMessage{Role: "user", Content: dataContext + "\n\nUser: " + req.Message})

	response, err := h.router.Chat(ctx, systemPrompt, messages)
	if err != nil {
		// Show only the error — it already contains provider-specific actionable info
		errMsg := fmt.Sprintf("**%v**\n\nGo to **Settings → AI** to fix your provider configuration.", err)
		RespondJSON(w, http.StatusOK, map[string]interface{}{
			"answer": errMsg,
		})
		return
	}

	RespondJSON(w, http.StatusOK, map[string]interface{}{
		"answer": response,
	})
}

func noneStr(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// ListModels handles GET /api/v1/ai/models?provider=nim
func (h *AIHandler) ListModels(w http.ResponseWriter, r *http.Request) {
	provider := r.URL.Query().Get("provider")
	if provider == "" {
		provider = "nim"
	}

	ctx, cancel := context.WithTimeout(r.Context(), 35*time.Second)
	defer cancel()

	models, err := h.router.ListModels(ctx, provider)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "AI_ERROR", safeError(err, "list models"))
		return
	}

	if models == nil {
		models = []string{}
	}
	RespondJSON(w, http.StatusOK, models)
}

// anomalyRow represents an anomaly from the database.
type anomalyRow struct {
	ID          int     `json:"id"`
	Type        string  `json:"type"`
	Severity    string  `json:"severity"`
	Description string  `json:"description"`
	Context     []byte  `json:"context"`
	Resolved    bool    `json:"resolved"`
	CreatedAt   string  `json:"created_at"`
	ResolvedAt  *string `json:"resolved_at,omitempty"`
}

// ListAnomalies handles GET /api/v1/anomalies
func (h *AIHandler) ListAnomalies(w http.ResponseWriter, r *http.Request) {
	if h.pool == nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", "database not available")
		return
	}

	ctx := r.Context()
	rows, err := h.pool.Query(ctx,
		`SELECT id, type, severity, description, context, resolved, created_at::text, resolved_at::text
		 FROM anomalies ORDER BY created_at DESC LIMIT 100`)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "database"))
		return
	}
	defer rows.Close()

	var anomalies []anomalyRow
	for rows.Next() {
		var a anomalyRow
		if err := rows.Scan(&a.ID, &a.Type, &a.Severity, &a.Description, &a.Context,
			&a.Resolved, &a.CreatedAt, &a.ResolvedAt); err != nil {
			RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "database"))
			return
		}
		anomalies = append(anomalies, a)
	}

	if anomalies == nil {
		anomalies = []anomalyRow{}
	}
	RespondJSON(w, http.StatusOK, anomalies)
}

// ResolveAnomaly handles POST /api/v1/anomalies/:id/resolve
func (h *AIHandler) ResolveAnomaly(w http.ResponseWriter, r *http.Request) {
	if h.pool == nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", "database not available")
		return
	}

	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_ID", "invalid anomaly ID")
		return
	}

	ctx := r.Context()
	tag, err := h.pool.Exec(ctx,
		`UPDATE anomalies SET resolved = true, resolved_at = NOW() WHERE id = $1`, id)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "database"))
		return
	}
	if tag.RowsAffected() == 0 {
		RespondError(w, http.StatusNotFound, "NOT_FOUND", "anomaly not found")
		return
	}

	RespondJSON(w, http.StatusOK, map[string]bool{"resolved": true})
}
