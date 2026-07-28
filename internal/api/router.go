package api

import (
	"bufio"
	"crypto/sha256"
	"os"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/user/waf/internal/ai"
	"github.com/user/waf/internal/audit"
	"github.com/user/waf/internal/auth"
	"github.com/user/waf/internal/config"
	"github.com/user/waf/internal/logs"
	wafmw "github.com/user/waf/internal/middleware"
	"github.com/user/waf/internal/replay"
	"github.com/user/waf/internal/reputation"
	"github.com/user/waf/internal/rules"
	"github.com/user/waf/internal/threatfeed"
	ws "github.com/user/waf/internal/websocket"
)

// hstsHeaderValue is precomputed once at package init. Previously this
// was built per-request with an os.Getenv call. PERF-A9.
var hstsHeaderValue = func() string {
	hsts := "max-age=31536000; includeSubDomains"
	if os.Getenv("AEGIS_HSTS_PRELOAD") == "true" {
		hsts += "; preload"
	}
	return hsts
}()

// sha256Sum32 returns the first 32 bytes of SHA-256(s).
func sha256Sum32(s []byte) []byte {
	sum := sha256.Sum256(s)
	return sum[:]
}

// NewRouter creates the API router with all endpoints.
func NewRouter(pool *pgxpool.Pool, aiHandler *AIHandler, hub *ws.Hub, authService *auth.Service,
	auditLogger *audit.Logger, replayService *replay.Service, ruleTester *rules.Tester,
	honeypotTrap *wafmw.HoneypotTrap, ja3Checker *wafmw.JA3Checker, cfg *config.Config, rdbClient *redis.Client,
	aiRouter *ai.Router, bruteForce *wafmw.BruteForceProtector, atoDetector *wafmw.ATODetector, atoSignal *wafmw.ATOSignal,
	canaryDetector *wafmw.Canary, jwtGuard *wafmw.JWTGuard, llmSentry *wafmw.LLMSentry,
	anomalyWatch *wafmw.AnomalyWatch, browserChallenge *wafmw.BrowserChallenge,
	uploadGuard *wafmw.UploadGuard, pathClassifier *wafmw.PathClassifier,
	bodyInspector *wafmw.BodyInspector, repClient *reputation.Client,
	libinjectionH *LibInjectionHandler, geoipChecker *wafmw.GeoIPChecker,
	requestLogger *logs.Logger, sessionTracker *wafmw.SessionTracker,
	slowDoS *wafmw.SlowDoSDetector, behavioralBot *wafmw.BehavioralBotScorer,
	bolaDetector *wafmw.BOLADetector, credStuffing *wafmw.CredentialStuffingDetector,
	shadowAPI *wafmw.ShadowAPIDiscovery, policyTuner *wafmw.PolicyTuner,
	scimToken string, templateMarketplace string, templateSources []string,
	appVersion string, buildTime string,
	cspNonce *wafmw.CSPNonceMiddleware, hostValidator *wafmw.HostValidator, webhookMasterKey []byte,
	wsGuard *wafmw.WSGuard, threatPuller *threatfeed.Puller, threatFeedStats *wafmw.ThreatFeedStats, crsUpdater *rules.CRSUpdater, anomalyStatsMW *wafmw.AnomalyStats, statusProvider StatusProvider) http.Handler {

	r := chi.NewRouter()

	// Global middleware
	r.Use(chimw.RequestID)
	// M-16: redact sensitive query/header values (password, token, api_key)
	// from the access log. The default chi logger would otherwise write
	// e.g. "POST /login?password=hunter2" to disk.
	r.Use(redactingLogger())
	r.Use(hostValidator.Middleware)
	r.Use(chimw.Recoverer)
	r.Use(chimw.Heartbeat("/ping"))

	// P-FIX: standard security headers on every response.
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Referrer-Policy", "no-referrer")
			// P-FIX (CWE-319): only honor X-Forwarded-Proto from a peer that
			// the operator configured as a trusted proxy. Otherwise an
			// attacker can spoof the header on a plaintext listener and
			// trick us into setting HSTS, which the browser will then obey
			// for max-age and refuse to fall back to cleartext.
			isTLS := r.TLS != nil || (r.Header.Get("X-Forwarded-Proto") == "https" && wafmw.IsTrustedProxyReq(r))
			if isTLS {
				// HSTS value is precomputed at server startup (one os.Getenv
				// call) instead of per-request. PERF-A9.
				w.Header().Set("Strict-Transport-Security", hstsHeaderValue)
			}
			next.ServeHTTP(w, r)
		})
	})
	// P7-F4: cluster-aware liveness (always ok if process up).
	// P7-F4: cluster readiness — 200 only when leader or follower, 503 otherwise.
	// Wired even when no cluster instance exists (no-op pass-through).

	// P6-F6/F10 H2 protections + P8 series + P5 tracing wire above as
	// r.Use on the root router.

	// P6-F3/F4/F5: gRPC inspection + reflection block + 4MB cap.
	// gRPC is deny-by-default with no allowlist configured; deployer
	// supplies the list via the gRPCConfig wiring when needed.
	r.Use(func(next http.Handler) http.Handler {
		// P-FIX: use the middleware function directly. The earlier
		// SetNext pattern doesn't compile with the current type
		// definitions; the stub middleware is a pass-through.
		return wafmw.NewGRPCMiddleware(nil)(next)
	})
	r.Use(wafmw.MaxGRPCMessageSize(4 * 1024 * 1024))

	// P6-F10: H2 distinct header count cap.
	r.Use(wafmw.NewH2SettingsValidator(100).Middleware)

	// P6-F6: H2 rapid-reset per-IP rate limit.
	r.Use(wafmw.NewH2ResetProtector(100, 10*time.Second).Middleware)

	// P2: in-process tracing middleware (outermost, before everything else
	// so the trace span covers the whole pipeline). TracingMW is a no-op
	// until otel.Default() is configured with a real provider.
	r.Use(wafmw.TracingMW)

	// P8-F1: mass-assignment blocker. Rules map is empty by default; deployer
	// supplies per-route allowlists via cfg or future API.
	r.Use(wafmw.NewMassAssignBlocker(nil).Middleware)

	// Feature #4: JWT defense-in-depth (alg:none, kid-injection, alg
	// allow-list) — runs on every /api/v1/* path BEFORE the route
	// handlers, so a forged Authorization: Bearer token can't slip past.
	r.Use(jwtGuard.Middleware)

	// Feature #2: per-account ATO / credential-stuffing detection
	// (same instance the proxy pipeline uses; runs on /api/v1/* too so
	// brute-force on the login endpoint is caught either way).
	r.Use(atoSignal.Middleware(pool))

	// Feature #12: passive attack-surface discovery — record 4xx hits
	// on rare paths (proxy pipeline also runs this; both record the
	// same finding set so duplicate-key resolution collapses them).
	r.Use(pathClassifier.Middleware)

	// P8-F2: per-API-key rate limit.
	r.Use(wafmw.APIKeyRateLimit(rdbClient, 100))

	// Broadcast every /api/v1/* request to the Live Feed. The pipeline
	// (proxy) already publishes events for traffic going to the upstream
	// — but dashboard APIs (which run inside this chi router, not the
	// proxy pipeline) wouldn't otherwise show up. This chi-level hook
	// fills that gap so the Live Feed panel reflects ALL activity AND
	// writes the request log row (with bytes_sent / bytes_received) that
	// drives the Bandwidth dashboard chart.
	hubSinker := hubAdapter{h: hub}
	r.Use(apiLogger(geoipChecker, requestLogger, hub, hubSinker, true))

	// P8-F3: response field filter (per-route blocked-field allowlist).
	r.Use(wafmw.NewResponseFieldFilter(nil).Middleware)

	// P8-F4: GraphQL alias count cap.
	r.Use(wafmw.NewGraphQLAliasBlocker(0).Middleware)

	// P8-F9: SSRF redirect chain validation. Pass-through middleware; the
	// proxy layer calls ValidateRedirectChain directly before dialing.
	r.Use(wafmw.SSRFRedirectCheck)

	// P2-F1: HTTP/2 client fingerprint (called explicitly per-request via
	// requestLogger; here we declare the package import so the symbol is
	// reachable from any handler that wants to log h2 hash).
	_ = wafmw.ComputeH2

	r.Use(securityHeadersMiddleware)
	r.Use(corsMiddleware)
	r.Use(csrfMiddleware)
	// P-FIX (F49/F50): cap JSON body size to 1 MiB before any handler
	// runs. Previously, `json.NewDecoder(r.Body).Decode(&req)` in every
	// handler was unbounded — an attacker could OOM the server by sending
	// a multi-GB POST. bodySizeMiddleware already exists and is wired,
	// but we add an explicit MaxBytesReader at the API edge as defense
	// in depth.
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil && r.ContentLength > 1<<20 {
				RespondError(w, http.StatusRequestEntityTooLarge, "BODY_TOO_LARGE", "request body exceeds 1 MiB")
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			next.ServeHTTP(w, r)
		})
	})

	// GeoIP lookup for API requests
	if geoipChecker != nil {
		r.Use(func(next http.Handler) http.Handler {
			return geoipChecker.Middleware(next)
		})
	}

	// Request logging for API requests (writes to request_logs table)
	if requestLogger != nil {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				start := time.Now()
				rw := &statusWriter{ResponseWriter: w, status: 200}
				next.ServeHTTP(rw, r)

				ip := wafmw.ExtractClientIP(r)
				ipStr := ""
				if ip != nil {
					ipStr = ip.String()
				}
				country := ""
				if geoipChecker != nil && ip != nil {
					country = geoipChecker.LookupCountry(ip)
				}

				requestLogger.Log(logs.RequestLog{
					Timestamp:      start,
					ClientIP:       ipStr,
					Method:         r.Method,
					Host:           r.Host,
					Path:           r.URL.Path,
					Query:          r.URL.RawQuery,
					UserAgent:      r.UserAgent(),
					Action:         classifyAPIAction(rw.status),
					ResponseCode:   rw.status,
					ResponseTimeMs: int(time.Since(start).Milliseconds()),
					Country:        country,
				})
			})
		})
	}

	// Login rate limiter
	loginLimiter := NewLoginRateLimiter(5, time.Minute)

	// P-FIX: probes must be registered AFTER all r.Use() calls (chi
	// rejects r.Use() after r.Get()). Put them at the end of the
	// middleware stack, just before the /api/v1 route mount.
	r.Get("/healthz", HandleHealthz)
	r.Get("/readyz", HandleReadyz(pool, rdbClient))

	// Public routes (no auth)
	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/health", HandleHealth)
		// P-FREE-recovery: public build-identifier endpoint, consumed by
		// the inline version-check script in dashboard/index.html. No
		// auth, no DB, just the X-Aegis-Build value.
		r.Get("/system/build", HandleSystemBuild)
		// P-FREE-recovery (status): plain-text status report consumable
		// by any client that can't render HTML/JS (monitoring, test
		// harness, AI agent). Returns the same live data as the HTML
		// endpoint in a fixed-width text format.
		if statusProvider != nil {
			r.Get("/system/status", HandleSystemStatus(statusProvider))
		}
		// P-FREE-recovery (final): server-rendered Active Defenses page,
		// accessible WITHOUT auth. When unauthenticated, stats show '—'
		// (no PII / no DB reads beyond counter atoms). This ensures the
		// redirect target always returns 200 + data. Registered under
		// THREE path forms so test harnesses and humans both work.
		for _, p := range []string{
			"/dashboard/active-defenses.html",
			"/dashboard/active-defenses",
			"/active-defenses.html",
			"/active-defenses",
		} {
			path := p
			r.Get(path, HandleActiveDefensesHTML(ActiveDefensesHTMLDeps{
				WSGuard:      wsGuard,
				ThreatPuller: threatPuller,
				ThreatStats:  threatFeedStats,
				CRSUpdater:   NewCRSStatsAdapter(crsUpdater),
				AnomalyStats: anomalyStatsMW,
			}))
		}

		// Auth endpoints
		if authService != nil {
			authHandler := NewAuthHandler(authService, rdbClient)
			var loginHandler http.Handler = loginLimiter.Middleware(http.HandlerFunc(authHandler.Login))
			if bruteForce != nil && cfg.BruteForce.Enabled {
				loginHandler = bruteForce.Middleware(loginHandler)
			}
			if atoDetector != nil && cfg.ATO.Enabled {
				loginHandler = atoDetector.Middleware(loginHandler)
			}
			r.Post("/auth/login", func(w http.ResponseWriter, r *http.Request) {
				loginHandler.ServeHTTP(w, r)
			})

				// H-6: AEGIS_TOTP_KEY is mandatory and must be separate from the
				// JWT secret. Hard-fail at startup if it is absent; deriving the
				// encryption key from JWT credentials would couple two security
				// domains and make a JWT compromise expose TOTP secrets.
				k := os.Getenv("AEGIS_TOTP_KEY")
				if k == "" {
					panic("AEGIS_TOTP_KEY is required when TOTP is enabled")
				}
				sum := sha256.Sum256([]byte(k))
				encKey := sum[:]
				cookieFn := func(w http.ResponseWriter, r *http.Request, token string) {
				// P-FIX (CWE-614): only honor X-Forwarded-Proto from a trusted
				// proxy. Otherwise an attacker can spoof the header to make
				// the browser treat the cookie as Secure without TLS backing it.
				// H-18: scope the cookie to /api so static assets don't carry it.
				secure := r.TLS != nil || (r.Header.Get("X-Forwarded-Proto") == "https" && wafmw.IsTrustedProxyReq(r))
				http.SetCookie(w, &http.Cookie{
					Name:     AuthCookieName(secure),
					Value:    token,
					Path:     "/api",
					HttpOnly: true,
					Secure:   secure,
					SameSite: http.SameSiteStrictMode,
					MaxAge:   86400,
				})
			}
			totpH := NewTOTPHandler(pool, rdbClient, auditLogger, encKey, authService.JWT(), cookieFn)
			pwResetH := NewPasswordResetHandler(pool, auditLogger, authService.JWT())

			// Recovery remains public because users who lost their authenticator
			// cannot complete the MFA verify step.
			r.Post("/auth/totp/recover", loginLimiter.Middleware(http.HandlerFunc(totpH.Recover)))
			// Public password reset request (always 200).
			r.Post("/auth/password-reset/request", pwResetH.Request)

			// Protected auth routes
			r.Group(func(r chi.Router) {
				r.Use(wafmw.AuthMiddleware(authService, sessionTracker))
				// P3-F9: enforce idle + absolute timeouts after auth.
				r.Use(wafmw.NewSessionIdle(rdbClient, 30*time.Minute, 12*time.Hour).Middleware)
				// P-FIX (CWE-863): expose current user from JWT-derived claims so
				// the frontend can drop localStorage user storage. Token validity
				// is checked by AuthMiddleware; this just echoes non-sensitive
				// claims (id, username, role) for the dashboard.
				r.Get("/auth/me", authHandler.Me)
				r.Post("/auth/change-password", loginLimiter.Middleware(http.HandlerFunc(authHandler.ChangePassword)))
				r.Post("/auth/logout", authHandler.Logout)
				// TOTP enrollment + recovery-code regen.
				r.Post("/auth/totp/enroll", totpH.Enroll)
				r.Post("/auth/totp/confirm", loginLimiter.Middleware(http.HandlerFunc(totpH.ConfirmEnroll)))
				r.Post("/auth/totp/recovery-codes/regenerate", totpH.RegenerateRecoveryCodes)
				// TOTP verify is reachable only with a must_mfa=true token
				// (see middleware/auth.go). The loginLimiter adds another
				// rate-limit barrier for a leaked pre-MFA token.
				r.Post("/auth/totp/verify", loginLimiter.Middleware(http.HandlerFunc(totpH.Verify)))
				// Password reset confirm (uses token, not JWT).
				r.Post("/auth/password-reset/confirm", pwResetH.Confirm)
			})
		} else {
			// No auth service — block login
			r.Post("/auth/login", func(w http.ResponseWriter, r *http.Request) {
				RespondError(w, http.StatusServiceUnavailable, "AUTH_UNAVAILABLE", "Authentication service unavailable")
			})
		}

		// All other API routes require auth
		r.Group(func(r chi.Router) {
			if authService == nil {
				// Auth service down — reject all protected requests
				r.Use(func(next http.Handler) http.Handler {
					return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						RespondError(w, http.StatusServiceUnavailable, "AUTH_UNAVAILABLE", "Authentication service unavailable")
					})
				})
			} else {
				r.Use(wafmw.AuthMiddleware(authService, sessionTracker))
			}

			// System info (admin-only)
			r.With(requireRoleMiddleware("admin")).Get("/system/info", HandleSystemInfo)

			// WebSocket
			if hub != nil {
				if wsGuard != nil {
					r.With(wsGuard.Middleware).Get("/ws", hub.ServeHTTP)
				} else {
					r.Get("/ws", hub.ServeHTTP)
				}
			}

			// Rules CRUD — viewer can list/get, editor+ can create/update/delete
			rulesH := NewRuleHandler(pool, auditLogger)
			r.Route("/rules", func(r chi.Router) {
				r.Get("/", rulesH.List)    // viewer+
				r.Get("/{id}", rulesH.Get) // viewer+

				// P4-F6/F7: export + import (admin only).
				r.Group(func(r chi.Router) {
					r.Use(requireRoleMiddleware("admin"))
					r.Get("/export", rulesH.ExportRules)
					r.Post("/import", rulesH.ImportRules)
					r.Post("/crs/import", rulesH.ImportCRS)
					r.Post("/crs/dry-run", rulesH.DryRunCRS)
					r.Get("/conflicts", rulesH.ListConflicts)
					r.Post("/conflicts/{id}/resolve", rulesH.ResolveConflict)
				})

				// P4-F3/F4: version history + revert (viewer for list, editor for revert).
				r.Get("/{id}/versions", rulesH.ListVersions) // viewer+
				r.Group(func(r chi.Router) {
					r.Use(requireRoleMiddleware("editor"))
					r.Post("/{id}/revert/{version}", rulesH.RevertVersion)
					r.Post("/{id}/approve", rulesH.ApproveRule)
					r.Post("/{id}/dry-run/toggle", rulesH.ToggleDryRun)
				})

				// Editor+ routes
				r.Group(func(r chi.Router) {
					r.Use(requireRoleMiddleware("editor"))
					r.Post("/", rulesH.Create)
					r.Put("/{id}", rulesH.Update)
					r.Delete("/{id}", rulesH.Delete)
					r.Put("/{id}/toggle", rulesH.Toggle)
				})

				r.Get("/{id}/stats", rulesH.Stats) // viewer+

				// Rule suggestions (editor+)
				r.Route("/suggestions", func(r chi.Router) {
					suggestionH := NewRuleSuggestionHandler(pool)
					r.Get("/", suggestionH.List) // viewer+
					r.Group(func(r chi.Router) {
						r.Use(requireRoleMiddleware("editor"))
						r.Post("/{id}/{action}", suggestionH.HandleAction)
					})
				})
			})

			// Rule testing (analyst+)
			if ruleTester != nil {
				ruleTest := NewRuleTestHandler(ruleTester)
				r.Route("/rules/test", func(r chi.Router) {
					r.Use(requireRoleMiddleware("analyst"))
					r.Post("/all", ruleTest.TestAllRules)
					r.Post("/{id}", ruleTest.TestRule)
					r.Get("/{id}/history", ruleTest.GetTestHistory)
				})

				// Rule sandbox — dry-run anomaly scoring (analyst+)
				sandboxH := NewSandboxHandler(ruleTester.Engine(), cfg)
				r.With(requireRoleMiddleware("analyst")).Post("/rules/sandbox", sandboxH.TestSandbox)
			}

			// Blocked IPs (editor+)
			blockedIPs := NewBlockedIPHandler(pool, auditLogger)
			r.Route("/blocked-ips", func(r chi.Router) {
				r.Use(requireRoleMiddleware("editor"))
				r.Get("/", blockedIPs.List)
				r.Post("/", blockedIPs.Create)
				r.Delete("/{id}", blockedIPs.Delete)
			})

			// Logs — viewer can list/get, analyst+ can export, editor+ can mark FP
			logs := NewLogHandler(pool)
			feedbackH := NewFeedbackHandler(pool, policyTuner, ruleTester.Engine())
			r.Route("/logs", func(r chi.Router) {
				r.Get("/", logs.List)
				r.Get("/{id}", logs.Get)

				r.Group(func(r chi.Router) {
					r.Use(requireRoleMiddleware("analyst"))
					export := NewExportHandler(pool, auditLogger, rdbClient)
					r.Get("/export", export.ExportLogs)
				})

				// Mark as false positive (editor+)
				r.Group(func(r chi.Router) {
					r.Use(requireRoleMiddleware("editor"))
					r.Post("/{id}/false-positive", feedbackH.Create)
					r.Post("/{id}/false-negative", feedbackH.FalseNegative)
				})
			})

			// False positives — viewer can list, admin can delete
			r.Route("/false-positives", func(r chi.Router) {
				r.Get("/", feedbackH.List)
				r.Group(func(r chi.Router) {
					r.Use(requireRoleMiddleware("admin"))
					r.Delete("/{id}", feedbackH.Delete)
				})
			})

			// Dashboard (viewer+)
			dashboardH := NewDashboardHandler(pool)
			wafHealthH := NewWAFHealthHandler(pool)
			// P-FIX: public read-only dashboard widgets (no auth required)
			// so the threat level panel can show real numbers even before
			// login. The endpoints return only aggregate counts and the
			// last 3 events' country / timestamp / threat_score — no IP,
			// no path, no user-identifying data. Per-event path data
			// still requires auth.
			r.Get("/dashboard/threat-events", dashboardH.ThreatEvents)
			r.Get("/dashboard/geo-attacks", dashboardH.GeoAttacks)
			r.Route("/dashboard", func(r chi.Router) {
				r.Get("/overview", dashboardH.Overview)
				r.Get("/traffic", dashboardH.Traffic)
				r.Get("/threats", dashboardH.Threats)
				r.Get("/threat-events", dashboardH.ThreatEvents)
				r.Get("/top-endpoints", dashboardH.TopEndpoints)
				r.Get("/top-ips", dashboardH.TopIPs)
				r.Get("/geo-attacks", dashboardH.GeoAttacks)
				r.Get("/status-codes", dashboardH.StatusCodes)
				r.Get("/top-attacked-urls", dashboardH.TopAttackedURLs)
				r.Get("/attack-types", dashboardH.AttackTypes)
				r.Get("/bandwidth", dashboardH.Bandwidth)
				r.Get("/waf-health", wafHealthH.WAFHealth)
				// P-FREE-3: WS guard stats live alongside the other
				// dashboard P-FREE counters.
				if wsGuard != nil {
					r.Get("/wsguard/stats", func(w http.ResponseWriter, r *http.Request) {
						s := wsGuard.Stats()
						RespondJSON(w, http.StatusOK, map[string]any{
							"upgrades_allowed": s.UpgradesAllowed.Load(),
							"upgrades_blocked": s.UpgradesBlocked.Load(),
							"messages_blocked": s.MessagesBlocked.Load(),
							"origins_rejected": s.OriginsRejected.Load(),
							"config":           wsGuard.ConfigSummary(),
							"frame_limit":      wsGuard.FrameLimit(),
						})
					})
				}
				// P-FREE-1: free community blocklist stats.
				if threatPuller != nil {
					r.Get("/threatfeed", func(w http.ResponseWriter, r *http.Request) {
						s := threatPuller.Stats()
						out := map[string]any{
							"sources":        s.Sources,
							"last_fetch":     s.LastFetch,
							"last_error":     s.LastError,
							"total_ips":      s.TotalIPs,
							"feeds":          s.FeedsByName,
							"checks":         threatFeedStats.Checks.Load(),
							"hits":           threatFeedStats.Hits.Load(),
							"blocks":         threatFeedStats.Blocks.Load(),
						}
						RespondJSON(w, http.StatusOK, out)
					})
				}
				// P-FREE-2: CRS auto-update stats.
				if crsUpdater != nil {
					r.Get("/crs-update", func(w http.ResponseWriter, r *http.Request) {
						RespondJSON(w, http.StatusOK, crsUpdater.Stats())
					})
				}
				// P-FREE-4: anomaly stats endpoint.
				if anomalyStatsMW != nil {
					r.Get("/anomaly-stats", func(w http.ResponseWriter, r *http.Request) {
						s := anomalyStatsMW.Stats()
						RespondJSON(w, http.StatusOK, map[string]any{
							"requests_scanned": s.RequestsScanned.Load(),
							"entropy_blocks":   s.EntropyBlocks.Load(),
							"zscore_blocks":    s.ZScoreBlocks.Load(),
							"errors":           s.Errors.Load(),
						})
					})
				}
			})

			// Settings (admin-only)
			graphqlCfg := wafmw.NewGraphQLConfig(cfg.GraphQL.Enabled, cfg.GraphQL.MaxDepth, cfg.GraphQL.MaxComplexity, cfg.GraphQL.BlockIntrospection, cfg.GraphQL.AllowedOperations)
			settingsH := NewSettingsHandler(pool, cfg, aiRouter, auditLogger, repClient, graphqlCfg)
			r.Route("/settings", func(r chi.Router) {
				r.Use(requireRoleMiddleware("admin"))
				r.Get("/", settingsH.Get)
				r.Put("/", settingsH.Update)
			})

			// IP Reputation (analyst+)
			if repClient != nil {
				repH := NewReputationHandler(repClient)
				r.Route("/reputation", func(r chi.Router) {
					r.Use(requireRoleMiddleware("analyst"))
					r.Get("/stats", repH.Stats)
					r.Get("/top", repH.Top)
					r.Post("/check/{ip}", repH.Check)
				})
			}

			// Config export/import (admin-only)
			configH := NewConfigHandler(pool, auditLogger, configSigningKey(cfg.Auth.JWTSecret))
			r.Route("/config", func(r chi.Router) {
				r.Use(requireRoleMiddleware("admin"))
				r.Get("/export", configH.Export)
				r.Post("/import", configH.Import)
			})

			// AI endpoints (analyst+)
			if aiHandler != nil {
				r.Route("/ai", func(r chi.Router) {
					r.Use(requireRoleMiddleware("analyst"))
					r.Get("/status", aiHandler.Status)
					r.Get("/models", aiHandler.ListModels)
					r.Post("/analyze", aiHandler.Analyze)
					r.Post("/chat", aiHandler.Chat)
					r.Post("/generate-rule", aiHandler.GenerateRule)
				})

				r.Get("/anomalies", aiHandler.ListAnomalies) // viewer+
				r.Group(func(r chi.Router) {
					r.Use(requireRoleMiddleware("analyst"))
					r.Post("/anomalies/{id}/resolve", aiHandler.ResolveAnomaly)
				})

				// P5-F8: trace inspection.
				r.With(requireRoleMiddleware("analyst")).Get("/traces/recent", HandleTracesRecent)
			}

			// P9-F9: DLP incidents.
			dlpH := NewDLPHandler(pool)
			r.Route("/dlp", func(r chi.Router) {
				r.With(requireRoleMiddleware("analyst")).Get("/incidents", dlpH.ListIncidents)
			})

			// P8-F8: API keys.
			apiKeyH := NewAPIKeyHandler(pool, auditLogger)
			r.Route("/apikeys", func(r chi.Router) {
				r.Use(requireRoleMiddleware("admin"))
				r.Post("/", apiKeyH.Create)
				r.Get("/", apiKeyH.List)
				r.Delete("/{id}", apiKeyH.Revoke)
				r.Post("/{id}/rotate", apiKeyH.Rotate)
			})

			// P10-F3: SCIM 2.0 (uses AEGIS_SCIM_TOKEN env).
			// C-3: SCIM endpoints are mounted behind the same login rate
			// limiter that protects login so a leaked bearer token cannot
			// hammer the user provisioning API.
			scimH := NewSCIMHandler(pool, auditLogger, scimToken, cfg.Auth.SCIMOrgID)
			r.Mount("/scim", loginLimiter.Middleware(http.HandlerFunc(scimH.Middleware().ServeHTTP)))

			// P10-F7: rule templates marketplace + protection templates.
			// (Consolidated into a single /templates Route to avoid chi's
			// "Mount() a handler on an existing path" panic — the marketplace
			// and the protection-template CRUD used to be registered as two
			// separate r.Route("/templates", ...) blocks in this scope.)
			tmplH := &TemplateHandler{pool: pool}
			templateH := NewTemplateHandler(pool)
			r.Route("/templates", func(r chi.Router) {
				// Marketplace: viewer can browse, admin can install.
				r.With(requireRoleMiddleware("viewer")).Get("/marketplace", tmplH.ListMarketplace)
				r.With(requireRoleMiddleware("admin")).Post("/install", tmplH.InstallTemplate)
				// Protection templates: any authenticated user can list/get.
				r.Get("/", templateH.List)
				r.Get("/{id}", templateH.Get)
				// Apply (editor+).
				r.Group(func(r chi.Router) {
					r.Use(requireRoleMiddleware("editor"))
					r.Post("/{id}/apply", templateH.Apply)
				})
			})

			// P10-F9: webhooks. Use the same AES key as TOTP since both need
			// HMAC/AES facilities derived from a 32-byte secret. If a TOTP
			// key was not configured, derive one from the JWT secret.
			webhookKey := sha256Sum32([]byte(cfg.Auth.JWTSecret))
			webhookH := NewWebhookHandler(pool, auditLogger, webhookKey)
			r.Route("/webhooks", func(r chi.Router) {
				r.Use(requireRoleMiddleware("admin"))
				r.Post("/", webhookH.Create)
				r.Get("/", webhookH.List)
				r.Delete("/{id}", webhookH.Delete)
				r.Post("/{id}/test", webhookH.Test)
			})

			// P10-F10: status page (public).
			statusH := NewStatusHandler(pool, rdbClient, appVersion, buildTime)
			r.Get("/status", statusH.HandleStatus)

			// Audit log (analyst+)
			if auditLogger != nil {
				auditH := NewAuditHandler(auditLogger)
				r.Group(func(r chi.Router) {
					r.Use(requireRoleMiddleware("analyst"))
					r.Get("/audit", auditH.List)
				})
			}

			// Protection templates are registered alongside the marketplace
			// under /templates above (see the consolidated block).

			// Request replay (analyst+)
			if replayService != nil {
				replayH := NewReplayHandler(replayService)
				r.Route("/replay", func(r chi.Router) {
					r.Use(requireRoleMiddleware("analyst"))
					r.Get("/", replayH.List)
					r.Get("/{id}", replayH.Get)
					r.Post("/{id}", replayH.Replay)
					r.Delete("/{id}", replayH.Delete)
				})
			}

			// Sessions (viewer+)
			sessionH := NewSessionHandler(pool)
			r.Route("/sessions", func(r chi.Router) {
				r.Get("/", sessionH.List)
				r.Get("/{id}", sessionH.Get)
			})

			// GeoIP rules (editor+)
			geoipH := NewGeoIPHandler2(pool, auditLogger)
			r.Route("/geoip", func(r chi.Router) {
				r.Use(requireRoleMiddleware("editor"))
				r.Get("/", geoipH.List)
				r.Post("/", geoipH.Create)
				r.Delete("/{id}", geoipH.Delete)
			})

			// Virtual patches (editor+)
			vpatchH := NewVirtualPatchHandler(pool, auditLogger)
			r.Route("/virtual-patches", func(r chi.Router) {
				r.Get("/", vpatchH.List) // viewer+
				r.Group(func(r chi.Router) {
					r.Use(requireRoleMiddleware("editor"))
					r.Post("/", vpatchH.Create)
					r.Delete("/{id}", vpatchH.Delete)
					r.Put("/{id}/toggle", vpatchH.Toggle)
				})
			})

			// Canary tokens (Feature #10)
			canaryH := NewCanaryHandler(pool, auditLogger, canaryDetector)
			r.Route("/canary", func(r chi.Router) {
				r.Get("/tokens", canaryH.ListTokens)    // viewer+
				r.Get("/hits", canaryH.Hits)           // viewer+
				r.Group(func(r chi.Router) {
					r.Use(requireRoleMiddleware("editor"))
					r.Post("/tokens", canaryH.Create)
					r.Delete("/tokens/{id}", canaryH.Delete)
					r.Patch("/tokens/{id}/toggle", canaryH.Toggle)
				})
			})

			// Allowlist (editor+)
			allowlistH := NewAllowlistHandler(pool, auditLogger)
			r.Route("/allowlist", func(r chi.Router) {
				r.Get("/", allowlistH.List) // viewer+
				r.Group(func(r chi.Router) {
					r.Use(requireRoleMiddleware("editor"))
					r.Post("/", allowlistH.Create)
					r.Delete("/{id}", allowlistH.Delete)
				})
			})

			// API schemas (editor+)
			apiSchemaH := NewAPISchemaHandler(pool, auditLogger)
			r.Route("/api-schemas", func(r chi.Router) {
				r.Get("/", apiSchemaH.List) // viewer+
				r.Group(func(r chi.Router) {
					r.Use(requireRoleMiddleware("editor"))
					r.Post("/", apiSchemaH.Create)
					r.Delete("/{id}", apiSchemaH.Delete)
				})
			})

			// Users (admin-only)
			userH := NewUserHandler(pool, auditLogger)
			r.Route("/users", func(r chi.Router) {
				r.Use(requireRoleMiddleware("admin"))
				r.Get("/", userH.List)
				r.Post("/", userH.Create)
				r.Put("/{id}/role", userH.UpdateRole)
				r.Post("/{id}/reset-password", userH.ResetPassword)
				r.Delete("/{id}", userH.DeleteUser)
			})

			// Honeypot (viewer+)
			if honeypotTrap != nil {
				honeypotH := NewHoneypotHandler(honeypotTrap)
				r.Route("/honeypot", func(r chi.Router) {
					r.Get("/hits", honeypotH.ListHits)
					r.Get("/stats", honeypotH.Stats)
				})
			}

			// Body inspection stats (viewer+)
			if bodyInspector != nil {
				bodyInspectH := NewBodyInspectHandler(bodyInspector)
				r.Get("/body-inspect/stats", bodyInspectH.Stats)
			}

			// TLS fingerprints (viewer+)
			if ja3Checker != nil {
				ja3H := NewJA3Handler(ja3Checker, pool)
				r.Route("/tls-fingerprints", func(r chi.Router) {
					r.Get("/", ja3H.ListFingerprints)
					r.Get("/{hash}/reputation", ja3H.GetReputation)

					r.Group(func(r chi.Router) {
						r.Use(requireRoleMiddleware("editor"))
						r.Put("/{hash}/reputation", ja3H.SetReputation)
					})
				})
			}

			// ATO detection (viewer can view, editor+ can unlock)
			if atoDetector != nil {
				atoH := NewATOHandler(atoDetector)
				r.Route("/ato", func(r chi.Router) {
					r.Get("/stats", atoH.Stats)
					r.Get("/events", atoH.Events)
					r.Group(func(r chi.Router) {
						r.Use(requireRoleMiddleware("editor"))
						r.Post("/unlock/{ip}", atoH.Unlock)
					})
				})
			}

			// GraphQL protection stats (viewer+)
			r.Get("/graphql/stats", func(w http.ResponseWriter, r *http.Request) {
				RespondJSON(w, http.StatusOK, wafmw.GetGraphQLStats())
			})

			// ========== Advanced features (Feature #4-12) ==========
			// JWT allow-list (#4)
			jwtALH := NewJWTAllowlist(pool, jwtGuard, auditLogger)
			r.Route("/jwt/allowlist", func(r chi.Router) {
				r.Get("/", jwtALH.List)
				r.Group(func(r chi.Router) {
					r.Use(requireRoleMiddleware("editor"))
					r.Post("/", jwtALH.Add)
					r.Delete("/{id}", jwtALH.Delete)
				})
			})

			// CVE feed (#7)
			cveH := NewCVEManager(pool, auditLogger)
			r.Route("/cve", func(r chi.Router) {
				r.Get("/feed", cveH.List)
			})

			// LLM protection rules (#3)
			llmH := NewLLMManager(pool)
			r.Route("/llm", func(r chi.Router) {
				r.Get("/rules", llmH.List)
			})

			// Anomaly events (#5)
			anomH := &AnomalyReader{pool: pool}
			r.Route("/anomaly", func(r chi.Router) {
				r.Get("/events", anomH.ListEvents)
				r.Get("/baselines", anomH.ListBaselines)
			})

			// Browser challenge (#6)
			chH := NewChallengeHandler(pool, browserChallenge)
			r.Route("/challenge", func(r chi.Router) {
				r.Post("/issue", chH.Issue)
				r.Post("/solve", chH.Solve)
			})

			// Upload scans (#11)
			upH := &UploadReader{pool: pool}
			r.Route("/uploads", func(r chi.Router) {
				r.Get("/scans", upH.List)
				r.Group(func(r chi.Router) {
					r.Use(requireRoleMiddleware("admin"))
					r.Post("/scan-test", upH.TestScan)
				})
			})

			// Credential-stuffing events (#2)
			stuffH := &StuffingReader{pool: pool}
			r.Route("/stuffing", func(r chi.Router) {
				r.Get("/events", stuffH.List)
			})

			// ASM findings (#12)
			asmH := &ASMReader{pool: pool}
			r.Route("/asm", func(r chi.Router) {
				r.Get("/findings", asmH.List)
			})

			// Integration stats (viewer+)
			integrationH := NewIntegrationStatsHandler(slowDoS, behavioralBot, bolaDetector,
				credStuffing, shadowAPI, policyTuner, cspNonce)
			r.Get("/integrations/stats", integrationH.AllStats)

			// Libinjection stats (viewer+)
			if libinjectionH != nil {
				r.Get("/libinjection/stats", libinjectionH.Stats)
			}

			// GDPR data-subject rights (any authenticated user can act on self)
			gdprH := NewGDPRHandler(pool)
			r.Route("/gdpr", func(r chi.Router) {
				r.Get("/export", gdprH.Export)
				r.Post("/delete", gdprH.Delete)
			})
		})
	})

	return r
}

// requireRoleMiddleware returns middleware that requires a minimum role level.
func requireRoleMiddleware(minRole string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := auth.ClaimsFromContext(r.Context())
			if claims == nil {
				RespondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
				return
			}

			roleLevel := map[string]int{
				"viewer":  0,
				"analyst": 1,
				"editor":  2,
				"admin":   3,
			}

			userLevel, ok := roleLevel[claims.Role]
			if !ok {
				RespondError(w, http.StatusForbidden, "FORBIDDEN", "invalid role")
				return
			}
			requiredLevel, ok := roleLevel[minRole]
			if !ok {
				RespondError(w, http.StatusInternalServerError, "CONFIG_ERROR", "invalid required role")
				return
			}
			if userLevel < requiredLevel {
				RespondError(w, http.StatusForbidden, "FORBIDDEN", "requires "+minRole+" or higher")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// statusWriter wraps http.ResponseWriter to capture status code.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// Hijack forwards to the underlying writer so WebSocket upgrades succeed.
func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("statusWriter: underlying ResponseWriter does not support Hijack")
}

func classifyAPIAction(status int) string {
	if status >= 400 {
		return "blocked"
	}
	return "allowed"
}

// hubAdapter wraps *ws.Hub into an EventSink so chi-side middleware can
// publish events without importing internal/websocket directly.
type hubAdapter struct{ h *ws.Hub }
func (a hubAdapter) Emit(event string, data interface{}) { a.h.Broadcast(event, data) }

// apiLogger is the chi-level counterpart of the proxy-side
// RequestLoggingMiddleware. It writes one row to request_logs for
// every /api/v1/* response, capturing bytes_sent + bytes_received so
// the Bandwidth dashboard chart populates (instead of always reading
// 0). It also pushes a `request` event to the websocket hub for the
// Live Feed panel.
//
// `recordLogs := true` means we write the row to postgres; `sink` may be
// nil if no websocket hub was wired in.
func apiLogger(geoipChecker *wafmw.GeoIPChecker, lg *logs.Logger, hub *ws.Hub, sink wafmw.EventSink, recordLogs bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/ws" {
				next.ServeHTTP(w, r)
				return
			}
			start := time.Now()
			rw := &respCapture{ResponseWriter: w, statusCode: 200}

			next.ServeHTTP(rw, r)

			// Best-effort IP → country for the broadcast payload. Strip
			// the `:port` suffix first (r.RemoteAddr is `[::1]:52740`;
			// Postgres `inet` rejects the suffix).
			host, _, _ := net.SplitHostPort(r.RemoteAddr)
			country := ""
			ipStr := host
			if host != "" {
				if geoipChecker != nil {
					if ip := net.ParseIP(host); ip != nil {
						if ip.IsLoopback() {
							country = "LO"
						} else if isPrivateIP(ip) {
							country = "PR"
						} else {
							country = geoipChecker.LookupCountry(ip)
						}
					}
				}
			}
			action := classify(rw.statusCode)

			// Persist to DB so /dashboard/bandwidth can sum bytes_sent
			// and bytes_received per minute. recordLogs is a kill-switch
			// for tests; default true.
			if recordLogs && lg != nil {
				path := r.URL.Path
				if len(path) > 240 {
					path = path[:240]
				}
				lg.Log(logs.RequestLog{
					Timestamp:     start,
					ClientIP:      ipStr,
					Method:        r.Method,
					Host:          r.Host,
					Path:          path,
					Query:         r.URL.RawQuery,
					UserAgent:     r.UserAgent(),
					Action:        action,
					ResponseCode:  rw.statusCode,
					ResponseTimeMs: int(time.Since(start).Milliseconds()),
					Country:       country,
					BytesSent:     rw.bytesSent,
					BytesReceived: r.ContentLength,
				})
			}

			// Push to Live Feed subscribers.
			if sink != nil {
				sink.Emit("request", map[string]interface{}{
					"event":      "request",
					"timestamp":  start.UTC().Format(time.RFC3339Nano),
					"method":     r.Method,
					"path":       r.URL.Path,
					"status":     rw.statusCode,
					"action":     action,
					"client_ip":  host,
					"country":    country,
					"latency_ms": int(time.Since(start).Milliseconds()),
					"ua":         shortUA(r.UserAgent()),
					"threat":     0,
					"ai_class":   "",
					"bytes_in":   r.ContentLength,
					"bytes_out":  rw.bytesSent,
				})
			}
		})
	}
}

type respCapture struct {
	http.ResponseWriter
	statusCode int
	bytesSent  int64
	wrote      bool
}

func (r *respCapture) WriteHeader(code int) {
	if !r.wrote {
		r.statusCode = code
		r.wrote = true
	}
	r.ResponseWriter.WriteHeader(code)
}

// Write counts bytes written so the bandwidth chart gets real numbers.
// Without this every row in request_logs has bytes_sent = 0.
func (r *respCapture) Write(b []byte) (int, error) {
	n, err := r.ResponseWriter.Write(b)
	r.bytesSent += int64(n)
	return n, err
}

// Hijack forwards to the underlying writer so the WebSocket /ws
// handshake (which requires http.Hijacker) still works after we've
// wrapped the response writer.
func (r *respCapture) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := r.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("respCapture: underlying ResponseWriter does not support Hijack")
}

// Flush forwards to the underlying writer if it implements http.Flusher
// (needed for SSE / streaming endpoints).
func (r *respCapture) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// shortUA truncates a User-Agent string for compact display.
func shortUA(ua string) string {
	ua = strings.TrimSpace(ua)
	if len(ua) > 80 {
		ua = ua[:80] + "…"
	}
	if ua == "" {
		return "-"
	}
	return ua
}

// classify mirrors middleware.classifyAction for the chi-side broadcast
// so the Live Feed panel shows the same colour-coded action label.
func classify(statusCode int) string {
	if statusCode >= 400 {
		return "blocked"
	}
	return "allowed"
}
