package api

import (
	"context"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

type HealthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version"`
}

func HandleHealth(w http.ResponseWriter, r *http.Request) {
	RespondJSON(w, http.StatusOK, HealthResponse{
		Status:  "ok",
		Version: "0.1.0",
	})
}

// HandleHealthz is a lightweight liveness probe. Returns 200 OK if the
// process is up. Does not check downstream dependencies — that is the
// job of HandleReadyz.
func HandleHealthz(w http.ResponseWriter, r *http.Request) {
	RespondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// HandleReadyz returns a handler that checks Postgres and Redis
// connectivity. Returns 200 if both respond within the probe timeout,
// 503 otherwise. Suitable as a Kubernetes readiness probe.
func HandleReadyz(pool *pgxpool.Pool, rdb *redis.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		checks := map[string]string{"postgres": "ok", "redis": "ok"}
		ok := true
		if pool != nil {
			if err := pool.Ping(ctx); err != nil {
				checks["postgres"] = err.Error()
				ok = false
			}
		}
		if rdb != nil {
			if err := rdb.Ping(ctx).Err(); err != nil {
				checks["redis"] = err.Error()
				ok = false
			}
		}
		status := http.StatusOK
		overall := "ready"
		if !ok {
			status = http.StatusServiceUnavailable
			overall = "not_ready"
		}
		RespondJSON(w, status, map[string]any{
			"status": overall,
			"checks": checks,
		})
	}
}
