package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// APISchema represents a loaded OpenAPI spec for validation.
type APISchema struct {
	ID       int
	Name     string
	BasePath string
	Spec     json.RawMessage
	Enabled  bool
}

// SchemaValidator validates requests against API schemas.
type SchemaValidator struct {
	pool   *pgxpool.Pool
	mu     sync.RWMutex
	schemas []APISchema
	stopCh chan struct{}
}

// NewSchemaValidator creates a schema validator.
func NewSchemaValidator(pool *pgxpool.Pool, refreshInterval time.Duration) *SchemaValidator {
	v := &SchemaValidator{
		pool:   pool,
		stopCh: make(chan struct{}),
	}
	v.loadSchemas()
	go v.refreshLoop(refreshInterval)
	return v
}

func (v *SchemaValidator) refreshLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			v.loadSchemas()
		case <-v.stopCh:
			return
		}
	}
}

func (v *SchemaValidator) loadSchemas() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rows, err := v.pool.Query(ctx,
		`SELECT id, name, base_path, spec, enabled FROM api_schemas WHERE enabled = true`)
	if err != nil {
		log.Printf("schema: load: %v", err)
		return
	}
	defer rows.Close()

	var schemas []APISchema
	for rows.Next() {
		var s APISchema
		if err := rows.Scan(&s.ID, &s.Name, &s.BasePath, &s.Spec, &s.Enabled); err != nil {
			log.Printf("schema: scan: %v", err)
			continue
		}
		schemas = append(schemas, s)
	}

	v.mu.Lock()
	v.schemas = schemas
	v.mu.Unlock()
	log.Printf("schema: loaded %d API schemas", len(schemas))
}

// ValidateRequest checks if a request matches a known API schema.
// Returns nil if no schema matches or validation passes.
func (v *SchemaValidator) ValidateRequest(r *http.Request) *ValidationError {
	v.mu.RLock()
	defer v.mu.RUnlock()

	for _, schema := range v.schemas {
		if strings.HasPrefix(r.URL.Path, schema.BasePath) {
			// Basic validation: check Content-Type for POST/PUT/PATCH
			if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
				ct := r.Header.Get("Content-Type")
				if ct != "" && !strings.Contains(ct, "application/json") {
					return &ValidationError{
						Schema:  schema.Name,
						Message: "expected application/json content type",
					}
				}

				// Validate JSON body is parseable
				if r.Body != nil && strings.Contains(ct, "application/json") {
					body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MB limit
					if err != nil {
						return &ValidationError{
							Schema:  schema.Name,
							Message: "cannot read request body",
						}
					}
					r.Body.Close()
					r.Body = io.NopCloser(bytes.NewBuffer(body))

					if !json.Valid(body) {
						return &ValidationError{
							Schema:  schema.Name,
							Message: "invalid JSON body",
						}
					}
				}
			}
			break
		}
	}
	return nil
}

// Stop halts the background refresh loop.
func (v *SchemaValidator) Stop() {
	close(v.stopCh)
}

// ValidationError holds schema validation failure details.
type ValidationError struct {
	Schema  string
	Message string
}

// Middleware returns the schema validation middleware.
func (v *SchemaValidator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := v.ValidateRequest(r); err != nil {
			log.Printf("schema: validation failed for %s %s: %s", r.Method, sanitizeLog(r.URL.Path), sanitizeLog(err.Message))
			writeBlockError(w, "SCHEMA_VALIDATION", err.Message)
			return
		}
		next.ServeHTTP(w, r)
	})
}
