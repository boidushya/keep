package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Token-specific sentinel errors.
var (
	ErrTokenRevoked = errors.New("store: token revoked")
	ErrTokenExpired = errors.New("store: token expired")
)

// Token mirrors a tokens row. HashedToken is the hex sha256, never the
// plaintext.
type Token struct {
	ID          int
	ProjectID   int
	EnvID       int
	Name        string
	HashedToken string
	CreatedAt   int64
	LastUsedAt  sql.NullInt64
	ExpiresAt   sql.NullInt64
	RevokedAt   sql.NullInt64
}

// Tokens is the data access object for the tokens table. Mint creates plaintext
// for the user; the DB only ever sees the hex sha256.
type Tokens struct {
	DB  *sql.DB
	Now func() time.Time
}

func (t Tokens) now() int64 {
	if t.Now != nil {
		return t.Now().Unix()
	}
	return time.Now().Unix()
}

// Mint generates a fresh 32-byte plaintext token, stores its sha256, and
// returns both the plaintext (shown ONCE to the user) and the inserted row.
func (t Tokens) Mint(ctx context.Context, projectID, envID int, name string, expiresAt *int64) (string, Token, error) {
	plain, err := generatePlaintextToken()
	if err != nil {
		return "", Token{}, err
	}
	hashed := hashToken(plain)
	now := t.now()

	var expArg any
	if expiresAt != nil {
		expArg = *expiresAt
	}

	res, err := t.DB.ExecContext(ctx, `
		INSERT INTO tokens (project_id, env_id, name, hashed_token, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, projectID, envID, name, hashed, now, expArg)
	if err != nil {
		return "", Token{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return "", Token{}, err
	}

	row := Token{
		ID: int(id), ProjectID: projectID, EnvID: envID, Name: name,
		HashedToken: hashed, CreatedAt: now,
	}
	if expiresAt != nil {
		row.ExpiresAt = sql.NullInt64{Int64: *expiresAt, Valid: true}
	}
	return plain, row, nil
}

// Lookup hashes plaintext and returns the matching row. Returns ErrNotFound /
// ErrTokenRevoked / ErrTokenExpired in the relevant cases.
func (t Tokens) Lookup(ctx context.Context, plaintext string) (Token, error) {
	hashed := hashToken(plaintext)
	var r Token
	err := t.DB.QueryRowContext(ctx, `
		SELECT id, project_id, env_id, name, hashed_token, created_at,
		       last_used_at, expires_at, revoked_at
		FROM tokens
		WHERE hashed_token = ?
	`, hashed).Scan(
		&r.ID, &r.ProjectID, &r.EnvID, &r.Name, &r.HashedToken, &r.CreatedAt,
		&r.LastUsedAt, &r.ExpiresAt, &r.RevokedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Token{}, ErrNotFound
	}
	if err != nil {
		return Token{}, err
	}

	if r.RevokedAt.Valid {
		return Token{}, ErrTokenRevoked
	}
	if r.ExpiresAt.Valid && r.ExpiresAt.Int64 <= t.now() {
		return Token{}, ErrTokenExpired
	}
	return r, nil
}

// ListByEnv returns tokens for env, newest first.
func (t Tokens) ListByEnv(ctx context.Context, envID int) ([]Token, error) {
	rows, err := t.DB.QueryContext(ctx, `
		SELECT id, project_id, env_id, name, hashed_token, created_at,
		       last_used_at, expires_at, revoked_at
		FROM tokens
		WHERE env_id = ?
		ORDER BY created_at DESC, id DESC
	`, envID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Token
	for rows.Next() {
		var r Token
		if err := rows.Scan(
			&r.ID, &r.ProjectID, &r.EnvID, &r.Name, &r.HashedToken, &r.CreatedAt,
			&r.LastUsedAt, &r.ExpiresAt, &r.RevokedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// TouchLastUsed sets last_used_at to at.
func (t Tokens) TouchLastUsed(ctx context.Context, id int, at int64) error {
	_, err := t.DB.ExecContext(ctx,
		`UPDATE tokens SET last_used_at = ? WHERE id = ?`, at, id)
	return err
}

// Revoke sets revoked_at to now. Idempotent.
func (t Tokens) Revoke(ctx context.Context, id int) error {
	_, err := t.DB.ExecContext(ctx,
		`UPDATE tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
		t.now(), id)
	return err
}

// Get returns a token by id, ErrNotFound otherwise. Does not check revoked /
// expired (callers managing tokens want to see them in any state).
func (t Tokens) Get(ctx context.Context, id int) (Token, error) {
	var r Token
	err := t.DB.QueryRowContext(ctx, `
		SELECT id, project_id, env_id, name, hashed_token, created_at,
		       last_used_at, expires_at, revoked_at
		FROM tokens WHERE id = ?
	`, id).Scan(
		&r.ID, &r.ProjectID, &r.EnvID, &r.Name, &r.HashedToken, &r.CreatedAt,
		&r.LastUsedAt, &r.ExpiresAt, &r.RevokedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Token{}, ErrNotFound
	}
	return r, err
}

func generatePlaintextToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("rand token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func hashToken(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}
