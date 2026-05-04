package db

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
)

//go:embed migrations/*.sql
var embeddedMigrations embed.FS

// Migrate applies all embedded migrations to d. It is idempotent: rerunning
// applies only versions that have not yet been recorded.
func Migrate(ctx context.Context, d *sql.DB) error {
	return migrateFromFS(ctx, d, embeddedMigrations)
}

func migrateFromFS(ctx context.Context, d *sql.DB, src fs.FS) error {
	if err := ensureMigrationsTable(ctx, d); err != nil {
		return err
	}

	files, err := collectMigrations(src)
	if err != nil {
		return err
	}

	applied, err := loadAppliedVersions(ctx, d)
	if err != nil {
		return err
	}

	for _, m := range files {
		if applied[m.version] {
			continue
		}
		if err := applyMigration(ctx, d, m); err != nil {
			return fmt.Errorf("apply %s: %w", m.filename, err)
		}
	}
	return nil
}

func ensureMigrationsTable(ctx context.Context, d *sql.DB) error {
	_, err := d.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at INTEGER NOT NULL
		)
	`)
	return err
}

type migration struct {
	version  int
	filename string
	body     string
}

func collectMigrations(src fs.FS) ([]migration, error) {
	entries, err := fs.ReadDir(src, "migrations")
	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}

	var out []migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		v, err := parseVersion(e.Name())
		if err != nil {
			return nil, err
		}
		body, err := fs.ReadFile(src, path.Join("migrations", e.Name()))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", e.Name(), err)
		}
		out = append(out, migration{version: v, filename: e.Name(), body: string(body)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}

// parseVersion parses the leading integer from a filename like "0001_init.sql".
func parseVersion(name string) (int, error) {
	idx := strings.Index(name, "_")
	if idx <= 0 {
		return 0, fmt.Errorf("migration %q: expected NNNN_name.sql", name)
	}
	v, err := strconv.Atoi(name[:idx])
	if err != nil {
		return 0, fmt.Errorf("migration %q: leading number unparseable: %w", name, err)
	}
	return v, nil
}

func loadAppliedVersions(ctx context.Context, d *sql.DB) (map[int]bool, error) {
	rows, err := d.QueryContext(ctx, "SELECT version FROM schema_migrations")
	if err != nil {
		return nil, fmt.Errorf("read applied: %w", err)
	}
	defer rows.Close()

	out := map[int]bool{}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out[v] = true
	}
	return out, rows.Err()
}

func applyMigration(ctx context.Context, d *sql.DB, m migration) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, m.body); err != nil {
		return err
	}
	if _, err := tx.ExecContext(
		ctx,
		"INSERT INTO schema_migrations (version, applied_at) VALUES (?, strftime('%s', 'now'))",
		m.version,
	); err != nil {
		return err
	}
	return tx.Commit()
}
