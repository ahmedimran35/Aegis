package db

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// RunMigrations applies any SQL files in the migrations/ directory that have
// not yet been recorded in the schema_migrations table. Applied migrations
// are recorded transactionally so a failed migration aborts cleanly.
//
// Migrations are discovered at runtime (no go:embed) so the binary does not
// have to be rebuilt every time a new .up.sql file is added. Search path
// order:
//   1. $AEGIS_HOME/migrations
//   2. ./migrations
//   3. <exe-dir>/../migrations
func RunMigrations(pool *pgxpool.Pool) error {
	ctx := context.Background()

	_, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
        version TEXT PRIMARY KEY,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`)
	if err != nil {
		return fmt.Errorf("create migrations table: %w", err)
	}

	dir, err := locateMigrationsDir()
	if err != nil {
		return fmt.Errorf("locate migrations dir: %w", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read migrations dir %s: %w", dir, err)
	}

	var ups []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() {
			continue
		}
		// M-13: refuse symlinks. A malicious or buggy deploy that drops
		// a migration.sql -> /etc/passwd symlink could otherwise cause
		// us to "apply" arbitrary file contents as SQL.
		if e.Type()&os.ModeSymlink != 0 {
			log.Printf("migrate: skipping symlink %s (M-13)", name)
			continue
		}
		if strings.HasSuffix(name, ".up.sql") {
			ups = append(ups, name)
		}
	}
	sort.Strings(ups)

	for _, name := range ups {
		version := strings.TrimSuffix(name, ".up.sql")

		// M-13: re-check the entry is a regular file (the directory
		// listing could be racy between ReadDir and the open below).
		full := filepath.Join(dir, name)
		info, err := os.Lstat(full)
		if err != nil {
			return fmt.Errorf("stat migration %s: %w", name, err)
		}
		if !info.Mode().IsRegular() {
			log.Printf("migrate: skipping non-regular migration %s (M-13)", name)
			continue
		}

		var exists bool
		err = pool.QueryRow(ctx,
			"SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)",
			version).Scan(&exists)
		if err != nil {
			return fmt.Errorf("check migration %s: %w", version, err)
		}
		if exists {
			continue
		}

		sqlBytes, err := os.ReadFile(full)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}

		tx, err := pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin tx for %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, string(sqlBytes)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply migration %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx,
			"INSERT INTO schema_migrations (version) VALUES ($1)", version); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("record migration %s: %w", version, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit migration %s: %w", name, err)
		}
	}
	return nil
}

// locateMigrationsDir returns the first existing migrations/ directory
// from the search path.
func locateMigrationsDir() (string, error) {
	candidates := []string{}
	if home := os.Getenv("AEGIS_HOME"); home != "" {
		candidates = append(candidates, filepath.Join(home, "migrations"))
	}
	candidates = append(candidates, "migrations")
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "..", "migrations"))
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			return c, nil
		}
	}
	return "", fmt.Errorf("no migrations directory found (looked in %v)", candidates)
}