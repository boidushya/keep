package db

import (
	"context"
	"database/sql"
	"testing"
	"testing/fstest"
)

func TestMigrateAppliesEmbeddedFiles(t *testing.T) {
	t.Parallel()

	d, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	if err := Migrate(context.Background(), d); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	want := []string{
		"users",
		"master_key_envelope",
		"projects",
		"envs",
		"secrets",
		"secret_versions",
		"tokens",
		"audit_log",
		"schema_migrations",
	}
	for _, name := range want {
		var got string
		err := d.QueryRow(
			"SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?",
			name,
		).Scan(&got)
		if err != nil {
			t.Errorf("table %s missing: %v", name, err)
		}
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	t.Parallel()

	d, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	ctx := context.Background()
	if err := Migrate(ctx, d); err != nil {
		t.Fatalf("first migrate: %v", err)
	}

	first := countRows(t, d, "schema_migrations")

	if err := Migrate(ctx, d); err != nil {
		t.Fatalf("second migrate: %v", err)
	}

	second := countRows(t, d, "schema_migrations")
	if first != second {
		t.Fatalf("schema_migrations grew on re-run: %d -> %d", first, second)
	}
}

func TestMigrateAppliesNewFilesOnRerun(t *testing.T) {
	t.Parallel()

	d, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	ctx := context.Background()

	first := fstest.MapFS{
		"migrations/0001_a.sql": &fstest.MapFile{
			Data: []byte("CREATE TABLE a (id INTEGER PRIMARY KEY);"),
		},
	}
	if err := migrateFromFS(ctx, d, first); err != nil {
		t.Fatalf("first migrate: %v", err)
	}

	second := fstest.MapFS{
		"migrations/0001_a.sql": &fstest.MapFile{
			Data: []byte("CREATE TABLE a (id INTEGER PRIMARY KEY);"),
		},
		"migrations/0002_b.sql": &fstest.MapFile{
			Data: []byte("CREATE TABLE b (id INTEGER PRIMARY KEY);"),
		},
	}
	if err := migrateFromFS(ctx, d, second); err != nil {
		t.Fatalf("second migrate: %v", err)
	}

	for _, want := range []string{"a", "b"} {
		var got string
		err := d.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", want).Scan(&got)
		if err != nil {
			t.Errorf("table %q missing: %v", want, err)
		}
	}

	versions := schemaVersions(t, d)
	if !equalInts(versions, []int{1, 2}) {
		t.Fatalf("schema_migrations versions = %v, want [1 2]", versions)
	}
}

func TestMigrateRejectsMalformedFilename(t *testing.T) {
	t.Parallel()

	d, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	bad := fstest.MapFS{
		"migrations/notanumber_x.sql": &fstest.MapFile{
			Data: []byte("CREATE TABLE x (id INTEGER PRIMARY KEY);"),
		},
	}
	if err := migrateFromFS(context.Background(), d, bad); err == nil {
		t.Fatal("expected error for malformed filename, got nil")
	}
}

func countRows(t *testing.T, d *sql.DB, table string) int {
	t.Helper()
	var n int
	if err := d.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func schemaVersions(t *testing.T, d *sql.DB) []int {
	t.Helper()
	rows, err := d.Query("SELECT version FROM schema_migrations ORDER BY version")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []int
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		out = append(out, v)
	}
	return out
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
