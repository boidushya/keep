package store

import (
	"context"
	"errors"
	"testing"
)

func TestUsersGetEmptyReturnsErrNoUser(t *testing.T) {
	t.Parallel()

	s := Users{DB: newTestDB(t)}
	_, err := s.Get(context.Background())
	if !errors.Is(err, ErrNoUser) {
		t.Fatalf("err = %v, want ErrNoUser", err)
	}
}

func TestUsersCreateAndGet(t *testing.T) {
	t.Parallel()

	s := Users{DB: newTestDB(t)}
	ctx := context.Background()

	totp := []byte("totp-cipher")
	rec := []byte("rec-cipher")
	if err := s.Create(ctx, "hash$x", totp, rec); err != nil {
		t.Fatalf("create: %v", err)
	}

	u, err := s.Get(ctx)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if u.ID != 1 || u.PasswordHash != "hash$x" {
		t.Errorf("got %+v", u)
	}
	if string(u.TotpSecretEncrypted) != "totp-cipher" {
		t.Error("totp not stored verbatim")
	}
	if string(u.RecoveryCodesEncrypted) != "rec-cipher" {
		t.Error("recovery not stored verbatim")
	}
	if u.CreatedAt == 0 {
		t.Error("created_at not set")
	}
	if u.LastLoginAt.Valid {
		t.Error("last_login_at should be NULL on fresh user")
	}
}

func TestUsersCreateRejectsSecondUser(t *testing.T) {
	t.Parallel()

	s := Users{DB: newTestDB(t)}
	ctx := context.Background()

	if err := s.Create(ctx, "h1", []byte("a"), []byte("b")); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(ctx, "h2", []byte("c"), []byte("d")); err == nil {
		t.Fatal("expected error creating second user")
	}
}

func TestUsersUpdateLastLogin(t *testing.T) {
	t.Parallel()

	s := Users{DB: newTestDB(t)}
	ctx := context.Background()
	if err := s.Create(ctx, "h", []byte("a"), []byte("b")); err != nil {
		t.Fatal(err)
	}

	if err := s.UpdateLastLogin(ctx, 12345); err != nil {
		t.Fatal(err)
	}
	u, err := s.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !u.LastLoginAt.Valid || u.LastLoginAt.Int64 != 12345 {
		t.Fatalf("last_login_at = %+v", u.LastLoginAt)
	}
}

func TestUsersUpdateRecoveryCodes(t *testing.T) {
	t.Parallel()

	s := Users{DB: newTestDB(t)}
	ctx := context.Background()
	if err := s.Create(ctx, "h", []byte("a"), []byte("b")); err != nil {
		t.Fatal(err)
	}

	if err := s.UpdateRecoveryCodes(ctx, []byte("new")); err != nil {
		t.Fatal(err)
	}
	u, err := s.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(u.RecoveryCodesEncrypted) != "new" {
		t.Errorf("got %q", u.RecoveryCodesEncrypted)
	}
}
