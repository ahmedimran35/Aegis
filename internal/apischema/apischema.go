package apischema

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Schema represents an OpenAPI schema for validation.
type Schema struct {
	ID       int
	Name     string
	BasePath string
	Spec     map[string]interface{}
	enabled  bool
}

// Validator validates requests against OpenAPI schemas.
type Validator struct {
	pool    *pgxpool.Pool
	mu      sync.RWMutex
	schemas []Schema
	stopCh  chan struct{}
}

// NewValidator creates an API schema validator.
func NewValidator(pool *pgxpool.Pool, refreshInterval time.Duration) *Validator {
	v := &Validator{
		pool:   pool,
		stopCh: make(chan struct{}),
	}
	v.loadSchemas()
	go v.refreshLoop(refreshInterval)
	return v
}

func (v *Validator) refreshLoop(interval time.Duration) {
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

func (v *Validator) loadSchemas() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rows, err := v.pool.Query(ctx,
		`SELECT id, name, base_path, spec FROM api_schemas WHERE enabled = true`)
	if err != nil {
		log.Printf("apischema: load: %v", err)
		return
	}
	defer rows.Close()

	var schemas []Schema
	for rows.Next() {
		var s Schema
		var specBytes []byte
		if err := rows.Scan(&s.ID, &s.Name, &s.BasePath, &specBytes); err != nil {
			continue
		}
		if err := json.Unmarshal(specBytes, &s.Spec); err != nil {
			log.Printf("apischema: parse spec %d: %v", s.ID, err)
			continue
		}
		s.enabled = true
		schemas = append(schemas, s)
	}

	v.mu.Lock()
	v.schemas = schemas
	v.mu.Unlock()
	log.Printf("apischema: loaded %d schemas", len(schemas))
}

// Validate checks a request against matching OpenAPI schemas.
func (v *Validator) Validate(r *http.Request) *ValidationResult {
	v.mu.RLock()
	defer v.mu.RUnlock()

	path := r.URL.Path
	method := strings.ToLower(r.Method)

	for i := range v.schemas {
		s := &v.schemas[i]
		if !strings.HasPrefix(path, s.BasePath) {
			continue
		}

		// Find matching path in spec
		relPath := strings.TrimPrefix(path, s.BasePath)
		paths, ok := s.Spec["paths"].(map[string]interface{})
		if !ok {
			continue
		}

		pathItem, ok := paths[relPath].(map[string]interface{})
		if !ok {
			// Try with leading slash
			pathItem, ok = paths["/"+relPath].(map[string]interface{})
			if !ok {
				// Path not in schema
				if v.isStrictMode(s) {
					return &ValidationResult{
						Valid:   false,
						Message: fmt.Sprintf("path %s not defined in schema %s", relPath, s.Name),
						Schema:  s.Name,
					}
				}
				continue
			}
		}

		// Check method exists
		_, ok = pathItem[method]
		if !ok {
			if v.isStrictMode(s) {
				return &ValidationResult{
					Valid:   false,
					Message: fmt.Sprintf("method %s not allowed on %s", method, relPath),
					Schema:  s.Name,
				}
			}
			continue
		}

		// Validate Content-Type for request bodies
		if method == "post" || method == "put" || method == "patch" {
			ct := r.Header.Get("Content-Type")
			if ct != "" && !strings.HasPrefix(ct, "application/json") {
				return &ValidationResult{
					Valid:   false,
					Message: "expected application/json content type",
					Schema:  s.Name,
				}
			}
		}
	}

	return &ValidationResult{Valid: true}
}

func (v *Validator) isStrictMode(s *Schema) bool {
	strict, ok := s.Spec["x-strict-mode"]
	if !ok {
		return false
	}
	b, ok := strict.(bool)
	return ok && b
}

// ValidationResult holds the outcome of schema validation.
type ValidationResult struct {
	Valid   bool
	Message string
	Schema  string
}

// Stop halts the background refresh loop.
func (v *Validator) Stop() {
	close(v.stopCh)
}

// ListSchemas returns all loaded schemas.
func (v *Validator) ListSchemas(ctx context.Context) ([]map[string]interface{}, error) {
	rows, err := v.pool.Query(ctx,
		`SELECT id, name, base_path, enabled, created_at FROM api_schemas ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []map[string]interface{}
	for rows.Next() {
		var id int
		var name, basePath string
		var enabled bool
		var createdAt time.Time
		if err := rows.Scan(&id, &name, &basePath, &enabled, &createdAt); err != nil {
			continue
		}
		result = append(result, map[string]interface{}{
			"id":         id,
			"name":       name,
			"base_path":  basePath,
			"enabled":    enabled,
			"created_at": createdAt,
		})
	}
	return result, nil
}
