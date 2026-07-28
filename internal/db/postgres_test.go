package db

import (
	"context"
	"os"
	"testing"
)

func TestPostgresConnection(t *testing.T) {
	dsn := os.Getenv("AEGIS_TEST_DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://waf:wafpassword@localhost:5432/waf?sslmode=disable"
	}

	ctx := context.Background()
	pg, err := NewPostgres(ctx, dsn)
	if err != nil {
		t.Skipf("Postgres not available: %v", err)
	}
	defer pg.Close()

	if err := pg.Ping(ctx); err != nil {
		t.Fatalf("Ping() error: %v", err)
	}
}
