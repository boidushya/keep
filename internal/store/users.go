// Package store contains thin SQL data access objects, one per resource.
// Stores hold no business logic and no in-memory caching: handlers compose
// them.
package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// ErrNoUser indicates that the single-user table is empty.
var ErrNoUser = errors.New("store: no user")

// User mirrors the users table row.
type User struct {
	ID                     int
	PasswordHash           string
	TotpSecretEncrypted    []byte
	RecoveryCodesEncrypted []byte
	CreatedAt              int64
	LastLoginAt            sql.NullInt64
	TOTPVerified           bool
}

// Users provides access to the (single-row) users table.
type Users struct {
	DB  *sql.DB
	Now func() time.Time // optional, defaults to time.Now
}

func (u Users) now() int64 {
	if u.Now != nil {
		return u.Now().Unix()
	}
	return time.Now().Unix()
}

// Get returns the user. ErrNoUser when no row exists.
func (u Users) Get(ctx context.Context) (User, error) {
	var out User
	var verified int
	err := u.DB.QueryRowContext(ctx, `
		SELECT id, password_hash, totp_secret_encrypted, recovery_codes_encrypted,
		       created_at, last_login_at, totp_verified
		FROM users WHERE id = 1
	`).Scan(
		&out.ID, &out.PasswordHash, &out.TotpSecretEncrypted, &out.RecoveryCodesEncrypted,
		&out.CreatedAt, &out.LastLoginAt, &verified,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNoUser
	}
	out.TOTPVerified = verified != 0
	return out, err
}

// MarkTOTPVerified sets totp_verified=1 on the single user row.
func (u Users) MarkTOTPVerified(ctx context.Context) error {
	_, err := u.DB.ExecContext(ctx,
		`UPDATE users SET totp_verified = 1 WHERE id = 1`)
	return err
}

// Create inserts the (one and only) user row. Returns an error if a user
// already exists.
func (u Users) Create(ctx context.Context, passwordHash string, totpEnc, recoveryEnc []byte) error {
	_, err := u.DB.ExecContext(ctx, `
		INSERT INTO users (id, password_hash, totp_secret_encrypted,
		                   recovery_codes_encrypted, created_at)
		VALUES (1, ?, ?, ?, ?)
	`, passwordHash, totpEnc, recoveryEnc, u.now())
	return err
}

// UpdateLastLogin sets last_login_at on the single user row.
func (u Users) UpdateLastLogin(ctx context.Context, at int64) error {
	_, err := u.DB.ExecContext(ctx,
		`UPDATE users SET last_login_at = ? WHERE id = 1`, at)
	return err
}

// UpdateRecoveryCodes replaces the encrypted recovery-codes blob.
func (u Users) UpdateRecoveryCodes(ctx context.Context, encrypted []byte) error {
	_, err := u.DB.ExecContext(ctx,
		`UPDATE users SET recovery_codes_encrypted = ? WHERE id = 1`, encrypted)
	return err
}
