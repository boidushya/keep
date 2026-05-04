package store

import (
	"context"
	"database/sql"
	"testing"

	"github.com/boidushya/keep/internal/db"
)

// newTestDB returns an in-memory SQLite with migrations applied. The DB is
// closed automatically when the test ends.
func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	d, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	if err := db.Migrate(context.Background(), d); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return d
}
