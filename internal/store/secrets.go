package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Secret mirrors the secrets row plus the convenience fields callers consume.
type Secret struct {
	ID             int
	EnvID          int
	Key            string
	ValueEncrypted []byte
	CurrentVersion int
	UpdatedAt      int64
}

// SecretVersion mirrors a secret_versions row.
type SecretVersion struct {
	ID              int
	SecretID        int
	Version         int
	ValueEncrypted  []byte
	CreatedAt       int64
	CreatedByUserID sql.NullInt64
}

// Secrets is the data access object for secrets and secret_versions.
type Secrets struct {
	DB  *sql.DB
	Now func() time.Time
}

func (s Secrets) now() int64 {
	if s.Now != nil {
		return s.Now().Unix()
	}
	return time.Now().Unix()
}

// ListByEnv returns secrets for env, sorted by key.
func (s Secrets) ListByEnv(ctx context.Context, envID int) ([]Secret, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT id, env_id, key, value_encrypted, current_version, updated_at
		FROM secrets
		WHERE env_id = ?
		ORDER BY key ASC
	`, envID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Secret
	for rows.Next() {
		var r Secret
		if err := rows.Scan(&r.ID, &r.EnvID, &r.Key, &r.ValueEncrypted, &r.CurrentVersion, &r.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Get returns the secret by id, ErrNotFound otherwise.
func (s Secrets) Get(ctx context.Context, id int) (Secret, error) {
	var r Secret
	err := s.DB.QueryRowContext(ctx, `
		SELECT id, env_id, key, value_encrypted, current_version, updated_at
		FROM secrets WHERE id = ?
	`, id).Scan(&r.ID, &r.EnvID, &r.Key, &r.ValueEncrypted, &r.CurrentVersion, &r.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Secret{}, ErrNotFound
	}
	return r, err
}

// GetByKey returns the (envID, key) secret, ErrNotFound otherwise.
func (s Secrets) GetByKey(ctx context.Context, envID int, key string) (Secret, error) {
	var r Secret
	err := s.DB.QueryRowContext(ctx, `
		SELECT id, env_id, key, value_encrypted, current_version, updated_at
		FROM secrets WHERE env_id = ? AND key = ?
	`, envID, key).Scan(&r.ID, &r.EnvID, &r.Key, &r.ValueEncrypted, &r.CurrentVersion, &r.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Secret{}, ErrNotFound
	}
	return r, err
}

// Upsert inserts a new secret or appends a new version to an existing one.
// Atomic: writes secret_versions and updates secrets in a single transaction.
func (s Secrets) Upsert(ctx context.Context, envID int, key string, valueEnc []byte, byUserID int) (Secret, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Secret{}, err
	}
	defer func() { _ = tx.Rollback() }()

	now := s.now()

	var (
		secretID       int
		currentVersion int
	)
	err = tx.QueryRowContext(ctx,
		`SELECT id, current_version FROM secrets WHERE env_id = ? AND key = ?`,
		envID, key,
	).Scan(&secretID, &currentVersion)

	switch {
	case errors.Is(err, sql.ErrNoRows):
		res, err := tx.ExecContext(ctx, `
			INSERT INTO secrets (env_id, key, value_encrypted, current_version, updated_at)
			VALUES (?, ?, ?, 1, ?)
		`, envID, key, valueEnc, now)
		if err != nil {
			return Secret{}, err
		}
		id, err := res.LastInsertId()
		if err != nil {
			return Secret{}, err
		}
		secretID = int(id)
		currentVersion = 1
	case err != nil:
		return Secret{}, err
	default:
		currentVersion++
		if _, err := tx.ExecContext(ctx, `
			UPDATE secrets SET value_encrypted = ?, current_version = ?, updated_at = ?
			WHERE id = ?
		`, valueEnc, currentVersion, now, secretID); err != nil {
			return Secret{}, err
		}
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO secret_versions (secret_id, version, value_encrypted, created_at, created_by_user_id)
		VALUES (?, ?, ?, ?, ?)
	`, secretID, currentVersion, valueEnc, now, nullableUserID(byUserID)); err != nil {
		return Secret{}, err
	}

	if err := tx.Commit(); err != nil {
		return Secret{}, err
	}
	return Secret{
		ID: secretID, EnvID: envID, Key: key,
		ValueEncrypted: valueEnc, CurrentVersion: currentVersion, UpdatedAt: now,
	}, nil
}

func nullableUserID(id int) any {
	if id <= 0 {
		return nil
	}
	return id
}

// Delete removes a secret (cascading to its versions).
func (s Secrets) Delete(ctx context.Context, id int) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM secrets WHERE id = ?`, id)
	return err
}

// ListVersions returns versions for a secret, newest first.
func (s Secrets) ListVersions(ctx context.Context, secretID int) ([]SecretVersion, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT id, secret_id, version, value_encrypted, created_at, created_by_user_id
		FROM secret_versions
		WHERE secret_id = ?
		ORDER BY version DESC
	`, secretID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []SecretVersion
	for rows.Next() {
		var v SecretVersion
		if err := rows.Scan(&v.ID, &v.SecretID, &v.Version, &v.ValueEncrypted, &v.CreatedAt, &v.CreatedByUserID); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// RestoreVersion takes the value of (secretID, version) and writes it as a
// brand-new highest version. The history is never rewritten.
func (s Secrets) RestoreVersion(ctx context.Context, secretID, version, byUserID int) (Secret, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Secret{}, err
	}
	defer func() { _ = tx.Rollback() }()

	var oldValue []byte
	err = tx.QueryRowContext(ctx,
		`SELECT value_encrypted FROM secret_versions WHERE secret_id = ? AND version = ?`,
		secretID, version,
	).Scan(&oldValue)
	if errors.Is(err, sql.ErrNoRows) {
		return Secret{}, fmt.Errorf("store: secret %d has no version %d", secretID, version)
	} else if err != nil {
		return Secret{}, err
	}

	var current int
	if err := tx.QueryRowContext(ctx,
		`SELECT current_version FROM secrets WHERE id = ?`, secretID,
	).Scan(&current); err != nil {
		return Secret{}, err
	}
	newVersion := current + 1
	now := s.now()

	if _, err := tx.ExecContext(ctx, `
		UPDATE secrets SET value_encrypted = ?, current_version = ?, updated_at = ?
		WHERE id = ?
	`, oldValue, newVersion, now, secretID); err != nil {
		return Secret{}, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO secret_versions (secret_id, version, value_encrypted, created_at, created_by_user_id)
		VALUES (?, ?, ?, ?, ?)
	`, secretID, newVersion, oldValue, now, nullableUserID(byUserID)); err != nil {
		return Secret{}, err
	}
	if err := tx.Commit(); err != nil {
		return Secret{}, err
	}

	var envID int
	var key string
	if err := s.DB.QueryRowContext(ctx,
		`SELECT env_id, key FROM secrets WHERE id = ?`, secretID,
	).Scan(&envID, &key); err != nil {
		return Secret{}, err
	}

	return Secret{
		ID: secretID, EnvID: envID, Key: key,
		ValueEncrypted: oldValue, CurrentVersion: newVersion, UpdatedAt: now,
	}, nil
}
