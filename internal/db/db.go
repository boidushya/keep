// Package db opens the SQLite database used by keep and applies the runtime
// pragmas every connection needs (WAL, foreign keys, busy timeout). All other
// SQL lives in package-level stores.
package db

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// Open opens (or creates) the SQLite database at path and configures pragmas.
// Use ":memory:" for a transient test DB.
func Open(path string) (*sql.DB, error) {
	d, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("sqlite open: %w", err)
	}

	pragmas := []string{
		"PRAGMA journal_mode = WAL",
		"PRAGMA synchronous = NORMAL",
		"PRAGMA foreign_keys = ON",
		"PRAGMA busy_timeout = 5000",
	}
	for _, p := range pragmas {
		if _, err := d.Exec(p); err != nil {
			_ = d.Close()
			return nil, fmt.Errorf("pragma %q: %w", p, err)
		}
	}

	return d, nil
}
