package db

import (
	"context"
	"os"
	"testing"

	"github.com/user/waf/internal/config"
)

func TestRedisConnection(t *testing.T) {
	redisURL := os.Getenv("WAF_TEST_REDIS_URL")
	if redisURL == "" {
		redisURL = "redis://localhost:6379"
	}

	ctx := context.Background()
	r, err := NewRedis(ctx, config.RedisConfig{URL: redisURL})
	if err != nil {
		t.Skipf("Redis not available: %v", err)
	}
	defer r.Client.Close()

	if err := r.Client.Ping(ctx).Err(); err != nil {
		t.Fatalf("Ping() error: %v", err)
	}
}
