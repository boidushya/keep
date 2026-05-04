package store

import (
	"context"
	"database/sql"
)

// AuditEntry mirrors an audit_log row. Metadata is stored verbatim as JSON.
type AuditEntry struct {
	ID       int
	At       int64
	Actor    string
	Action   string
	Target   string
	Metadata string
}

// Audit is the data access object for audit_log.
type Audit struct {
	DB *sql.DB
}

// Append writes a new audit entry. If e.Metadata is empty we store "{}".
func (a Audit) Append(ctx context.Context, e AuditEntry) error {
	if e.Metadata == "" {
		e.Metadata = "{}"
	}
	_, err := a.DB.ExecContext(ctx, `
		INSERT INTO audit_log (at, actor, action, target, metadata)
		VALUES (?, ?, ?, ?, ?)
	`, e.At, e.Actor, e.Action, e.Target, e.Metadata)
	return err
}

// List returns up to limit entries with id < beforeID (or no upper bound when
// beforeID == 0). Newest first.
func (a Audit) List(ctx context.Context, limit, beforeID int) ([]AuditEntry, error) {
	q := `
		SELECT id, at, actor, action, target, metadata
		FROM audit_log
	`
	args := []any{}
	if beforeID > 0 {
		q += " WHERE id < ? "
		args = append(args, beforeID)
	}
	q += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit)

	rows, err := a.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.At, &e.Actor, &e.Action, &e.Target, &e.Metadata); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
