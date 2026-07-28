package middleware

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/text/unicode/norm"
)

// GraphQLConfig holds runtime GraphQL protection settings.
// Updated atomically via UpdateConfig for hot-reload.
type GraphQLConfig struct {
	enabled            int32  // atomic: 0=off, 1=on
	maxDepth           int32  // atomic
	blockIntrospection int32  // atomic: 0=allow, 1=block
	maxComplexity      int32  // atomic
	allowedOps         []string // guarded by mu
	mu                 sync.RWMutex
}

// GraphQLStats tracks GraphQL protection statistics.
type GraphQLStats struct {
	QueriesBlocked         atomic.Int64
	IntrospectionBlocked   atomic.Int64
	DepthViolations        atomic.Int64
	ComplexityViolations   atomic.Int64
	OperationViolations    atomic.Int64
	TotalQueries           atomic.Int64
	TotalDepth             atomic.Int64 // sum of all query depths for avg calculation
}

var graphqlStats GraphQLStats

// GetGraphQLStats returns current GraphQL stats.
func GetGraphQLStats() map[string]interface{} {
	total := graphqlStats.TotalQueries.Load()
	avgDepth := 0.0
	if total > 0 {
		avgDepth = float64(graphqlStats.TotalDepth.Load()) / float64(total)
	}
	return map[string]interface{}{
		"queries_blocked":         graphqlStats.QueriesBlocked.Load(),
		"introspection_blocked":   graphqlStats.IntrospectionBlocked.Load(),
		"depth_violations":        graphqlStats.DepthViolations.Load(),
		"complexity_violations":   graphqlStats.ComplexityViolations.Load(),
		"operation_violations":    graphqlStats.OperationViolations.Load(),
		"total_queries":           total,
		"avg_depth":               avgDepth,
	}
}

// NewGraphQLConfig creates a new runtime GraphQL config.
func NewGraphQLConfig(enabled bool, maxDepth, maxComplexity int, blockIntrospection bool, allowedOps []string) *GraphQLConfig {
	// F20: maxDepth lives in an int32 field used with atomics. The
	// previous code accepted any int and cast blindly, so a negative
	// value would wrap to a huge positive when stored (int32(-1) ==
	// 2147483647) and silently disable depth checks. Clamp into
	// [1, 1000] at construction time.
	if maxDepth <= 0 || maxDepth >= 1000 {
		log.Printf("graphql: maxDepth=%d out of range [1,1000); using default 10", maxDepth)
		maxDepth = 10
	}
	if maxComplexity <= 0 || maxComplexity >= 100000 {
		log.Printf("graphql: maxComplexity=%d out of range [1,100000); using default 100", maxComplexity)
		maxComplexity = 100
	}
	cfg := &GraphQLConfig{}
	if enabled {
		cfg.enabled = 1
	}
	cfg.maxDepth = int32(maxDepth)
	if blockIntrospection {
		cfg.blockIntrospection = 1
	}
	cfg.maxComplexity = int32(maxComplexity)
	cfg.allowedOps = allowedOps
	return cfg
}

// UpdateConfig hot-reloads GraphQL settings.
func (c *GraphQLConfig) UpdateConfig(enabled bool, maxDepth, maxComplexity int, blockIntrospection bool, allowedOps []string) {
	// F20 (mirror of NewGraphQLConfig clamp): applied at every reload to
	// keep the int32 atomic safe across operator-driven reloads too.
	if maxDepth <= 0 || maxDepth >= 1000 {
		log.Printf("graphql: maxDepth=%d out of range [1,1000); keeping previous value", maxDepth)
	} else {
		atomic.StoreInt32(&c.maxDepth, int32(maxDepth))
	}
	if enabled {
		atomic.StoreInt32(&c.enabled, 1)
	} else {
		atomic.StoreInt32(&c.enabled, 0)
	}
	if blockIntrospection {
		atomic.StoreInt32(&c.blockIntrospection, 1)
	} else {
		atomic.StoreInt32(&c.blockIntrospection, 0)
	}
	if maxComplexity <= 0 || maxComplexity >= 100000 {
		log.Printf("graphql: maxComplexity=%d out of range [1,100000); keeping previous value", maxComplexity)
	} else {
		atomic.StoreInt32(&c.maxComplexity, int32(maxComplexity))
	}
	c.mu.Lock()
	c.allowedOps = allowedOps
	c.mu.Unlock()
}

// IsEnabled returns whether GraphQL protection is active.
func (c *GraphQLConfig) IsEnabled() bool {
	return atomic.LoadInt32(&c.enabled) == 1
}

// graphqlRequestBody is the minimal JSON shape for a GraphQL request.
type graphqlRequestBody struct {
	Query         string                 `json:"query"`
	OperationName string                 `json:"operationName"`
	Variables     map[string]interface{} `json:"variables"`
}

// Regex patterns for GraphQL parsing.
var (
	// F29: extend the introspection regex to also catch curly-form
	// Unicode escapes (`\u{5f}`) used by GraphQL string interpolation
	// in some clients. The non-curly form is handled by the alternation
	// inside `(?:\\u005[fF]|\\u\{0*5[fF]\})?`.
	reIntrospection    = regexp.MustCompile(`(?i)(?:\\u005[fF]|\\u\{0*5[fF]\})?(?:_)(?:\\u005[fF]|\\u\{0*5[fF]\})?(?:_)(?:schema|type)\b`)
	reIntrospectionAlt = regexp.MustCompile(`(?i)__(?:schema|type)\b`)
	reOperationType    = regexp.MustCompile(`(?i)^\s*(query|mutation|subscription)\b`)
	reNamedOperation   = regexp.MustCompile(`(?i)(query|mutation|subscription)\s+(\w+)`)
	reBraceOpen        = regexp.MustCompile(`\{`)
	reBraceClose       = regexp.MustCompile(`\}`)
)

// normalizeForIntrospection applies NFKC normalization so that
// confusable characters such as fullwidth underscore (U+FF3F) or
// mathematical underscores cannot bypass the introspection filter.
// F44: defends against escape variants (`\u{5f}\u{5f}schema`,
// wide-char underscores, NFKC canonicalization).
func normalizeForIntrospection(query string) string {
	return norm.NFKC.String(strings.ToLower(query))
}

// Complexity weights for common field patterns.
var complexityWeights = map[string]int{
	"edges":       5,
	"nodes":       5,
	"pageInfo":    2,
	"totalCount":  3,
	"connection":  5,
	"list":        3,
	"search":      10,
	"aggregate":   8,
	"findMany":    5,
	"findFirst":   3,
	"users":       3,
	"posts":       3,
	"comments":    3,
	"replies":     3,
}

// GraphQLMiddleware detects and inspects GraphQL requests.
func GraphQLMiddleware(cfg *GraphQLConfig) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Fast path: skip if disabled
			if !cfg.IsEnabled() {
				next.ServeHTTP(w, r)
				return
			}

			// Only inspect POST requests with JSON content type
			if r.Method != http.MethodPost {
				next.ServeHTTP(w, r)
				return
			}
			ct := r.Header.Get("Content-Type")
			if !strings.HasPrefix(ct, "application/json") {
				next.ServeHTTP(w, r)
				return
			}

			// Read body (limit 512KB for GraphQL)
			if r.Body == nil || r.Body == http.NoBody {
				next.ServeHTTP(w, r)
				return
			}
			bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 512*1024))
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}
			// Restore body for downstream handlers
			r.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))

			// Try to parse as GraphQL request
			var reqBody graphqlRequestBody
			if err := json.Unmarshal(bodyBytes, &reqBody); err != nil {
				// Not a GraphQL request (invalid JSON or no query field)
				next.ServeHTTP(w, r)
				return
			}
			if reqBody.Query == "" {
				// Not a GraphQL request — no query field
				next.ServeHTTP(w, r)
				return
			}

			query := reqBody.Query
			graphqlStats.TotalQueries.Add(1)

			// --- Introspection blocking ---
			if atomic.LoadInt32(&cfg.blockIntrospection) == 1 {
				// F44: normalize before matching so confusables and
				// Unicode escape variants (`\u{5f}`) are caught.
				normalized := normalizeForIntrospection(query)
				if reIntrospection.MatchString(normalized) || reIntrospectionAlt.MatchString(normalized) {
					graphqlStats.IntrospectionBlocked.Add(1)
					graphqlStats.QueriesBlocked.Add(1)
					ip := extractIP(r)
					ipStr := ""
					if ip != nil {
						ipStr = ip.String()
					}
					log.Printf("graphql: BLOCKED introspection query from %s", sanitizeLog(ipStr))
					writeBlockError(w, "GRAPHQL_INTROSPECTION_BLOCKED",
						"GraphQL introspection queries are not allowed")
					return
				}
			}

			// --- Query depth limiting ---
			depth := calculateDepth(query)
			graphqlStats.TotalDepth.Add(int64(depth))
			maxD := int(atomic.LoadInt32(&cfg.maxDepth))
			if depth > maxD {
				graphqlStats.DepthViolations.Add(1)
				graphqlStats.QueriesBlocked.Add(1)
				log.Printf("graphql: BLOCKED query depth %d exceeds max %d", depth, maxD)
				writeBlockError(w, "GRAPHQL_DEPTH_EXCEEDED",
					fmt.Sprintf("query depth %d exceeds maximum allowed depth %d", depth, maxD))
				return
			}

			// --- Query complexity scoring ---
			complexity := calculateComplexity(query, depth)
			maxC := int(atomic.LoadInt32(&cfg.maxComplexity))
			if complexity > maxC {
				graphqlStats.ComplexityViolations.Add(1)
				graphqlStats.QueriesBlocked.Add(1)
				log.Printf("graphql: BLOCKED query complexity %d exceeds max %d", complexity, maxC)
				writeBlockError(w, "GRAPHQL_COMPLEXITY_EXCEEDED",
					fmt.Sprintf("query complexity %d exceeds maximum allowed complexity %d", complexity, maxC))
				return
			}

			// --- Operation whitelisting ---
			cfg.mu.RLock()
			allowedOps := cfg.allowedOps
			cfg.mu.RUnlock()
			if len(allowedOps) > 0 {
				opName := reqBody.OperationName
				if opName == "" {
					opName = extractOperationName(query)
				}
				if opName != "" && !isOperationAllowed(opName, allowedOps) {
					graphqlStats.OperationViolations.Add(1)
					graphqlStats.QueriesBlocked.Add(1)
					log.Printf("graphql: BLOCKED operation %q not in allowlist", sanitizeLog(opName))
					writeBlockError(w, "GRAPHQL_OPERATION_NOT_ALLOWED",
						fmt.Sprintf("operation %q is not in the allowed operations list", opName))
					return
				}
			}

			// Store GraphQL metadata in request metrics if available
			if m := MetricsFromContext(r.Context()); m != nil {
				// Set threat score contribution from complexity
				complexityScore := float64(complexity) / float64(maxC)
				if complexityScore > 0.8 {
					m.AIClassification = "suspicious"
				}
				if complexityScore > m.ThreatScore {
					m.ThreatScore = complexityScore
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// calculateDepth counts the maximum nesting depth of a GraphQL query by tracking brace depth.
// P-FIX: handles `"""` block strings (GraphQL spec §2.1.9) so a query
// like `{ a(s: """{""") b }` is not misparsed as a deeply-nested query.
func calculateDepth(query string) int {
	maxDepth := 0
	current := 0
	inString := false
	inBlockString := false
	escaped := false

	i := 0
	for i < len(query) {
		ch := query[i]

		// Block string """ ... """ — must check BEFORE plain string handling
		// because the sequence of three double-quotes can otherwise flip
		// inString state three times in a row.
		if !inString && i+2 < len(query) && query[i] == '"' && query[i+1] == '"' && query[i+2] == '"' {
			inBlockString = !inBlockString
			i += 3
			continue
		}
		if inBlockString {
			// Block strings end only on """. \n is literal. Escape is
			// not interpreted. Skip ahead.
			if ch == '\\' && i+1 < len(query) {
				i += 2
				continue
			}
			i++
			continue
		}

		if escaped {
			escaped = false
			i++
			continue
		}
		if ch == '\\' && inString {
			escaped = true
			i++
			continue
		}
		if ch == '"' {
			inString = !inString
			i++
			continue
		}
		if inString {
			i++
			continue
		}

		// Skip comments
		if ch == '#' {
			for i < len(query) && query[i] != '\n' {
				i++
			}
			continue
		}

		if ch == '{' {
			current++
			if current > maxDepth {
				maxDepth = current
			}
		} else if ch == '}' {
			if current > 0 {
				current--
			}
		}
		i++
	}

	return maxDepth
}

// aliasPattern precompiled once (was previously compiled on every
// calculateComplexity call).
var aliasPattern = regexp.MustCompile(`\w+\s*:`)

// calculateComplexity computes a complexity score for the query based on
// known field patterns. `depth` is passed in by the caller (already
// computed by `calculateDepth`) — avoids the duplicate regex/scan pass over
// the same query (PERF-A10).
func calculateComplexity(query string, depth int) int {
	score := 1 // base cost

	// Single ToLower call reused throughout.
	lower := strings.ToLower(query)

	// Add complexity for known expensive patterns
	for field, weight := range complexityWeights {
		if strings.Contains(lower, field) {
			score += weight
		}
	}

	// Add cost per nesting level (using the depth already computed).
	score += depth * 2

	// Add cost for variables
	score += strings.Count(query, "$")

	// Add cost for fragments
	score += strings.Count(lower, "fragment") * 5

	// Add cost for aliases (use precompiled regex; subtract keyword matches)
	aliasCount := len(aliasPattern.FindAllString(query, -1))
	for _, kw := range []string{"query", "mutation", "subscription", "fragment"} {
		aliasCount -= strings.Count(lower, kw+":")
	}
	if aliasCount > 0 {
		score += aliasCount * 2
	}

	return score
}

// extractOperationName gets the named operation from the query.
func extractOperationName(query string) string {
	match := reNamedOperation.FindStringSubmatch(query)
	if len(match) >= 3 {
		return match[2]
	}
	return ""
}

// isOperationAllowed checks if an operation name is in the allowlist.
func isOperationAllowed(name string, allowed []string) bool {
	for _, a := range allowed {
		if strings.EqualFold(a, name) {
			return true
		}
	}
	return false
}
