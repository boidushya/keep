package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func setupForTokens(t *testing.T) (Tokens, Project, Env) {
	t.Helper()
	d := newTestDB(t)
	ctx := context.Background()
	p, err := (Projects{DB: d}).Create(ctx, "lyrics-api", "Lyrics API")
	if err != nil {
		t.Fatal(err)
	}
	e, err := (Envs{DB: d}).Create(ctx, p.ID, "prod", "Prod")
	if err != nil {
		t.Fatal(err)
	}
	return Tokens{DB: d}, p, e
}

func TestTokensMintAndLookup(t *testing.T) {
	t.Parallel()

	ts, p, e := setupForTokens(t)
	ctx := context.Background()

	plain, row, err := ts.Mint(ctx, p.ID, e.ID, "hetzner-prod", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(plain) < 32 {
		t.Errorf("plaintext too short: %d", len(plain))
	}
	if row.ID == 0 || row.Name != "hetzner-prod" || row.HashedToken == plain {
		t.Errorf("row %+v should not store plaintext", row)
	}

	got, err := ts.Lookup(ctx, plain)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != row.ID {
		t.Error("lookup returned wrong row")
	}
}

func TestTokensLookupRejectsRevoked(t *testing.T) {
	t.Parallel()

	ts, p, e := setupForTokens(t)
	ctx := context.Background()
	plain, row, _ := ts.Mint(ctx, p.ID, e.ID, "h", nil)
	if err := ts.Revoke(ctx, row.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := ts.Lookup(ctx, plain); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("err = %v, want ErrTokenRevoked", err)
	}
}

func TestTokensLookupRejectsExpired(t *testing.T) {
	t.Parallel()

	ts, p, e := setupForTokens(t)
	ts.Now = func() time.Time { return time.Unix(1000, 0) }
	ctx := context.Background()

	exp := int64(500) // already past at ts.Now()
	plain, _, err := ts.Mint(ctx, p.ID, e.ID, "h", &exp)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ts.Lookup(ctx, plain); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("err = %v, want ErrTokenExpired", err)
	}
}

func TestTokensLookupUnknownReturnsNotFound(t *testing.T) {
	t.Parallel()

	ts, _, _ := setupForTokens(t)
	if _, err := ts.Lookup(context.Background(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestTokensTouchLastUsed(t *testing.T) {
	t.Parallel()

	ts, p, e := setupForTokens(t)
	ctx := context.Background()
	plain, row, _ := ts.Mint(ctx, p.ID, e.ID, "h", nil)

	if err := ts.TouchLastUsed(ctx, row.ID, 12345); err != nil {
		t.Fatal(err)
	}
	got, err := ts.Lookup(ctx, plain)
	if err != nil {
		t.Fatal(err)
	}
	if !got.LastUsedAt.Valid || got.LastUsedAt.Int64 != 12345 {
		t.Fatalf("last_used_at = %+v", got.LastUsedAt)
	}
}

func TestTokensListByEnv(t *testing.T) {
	t.Parallel()

	ts, p, e := setupForTokens(t)
	ctx := context.Background()
	for _, n := range []string{"a", "b"} {
		if _, _, err := ts.Mint(ctx, p.ID, e.ID, n, nil); err != nil {
			t.Fatal(err)
		}
	}
	got, err := ts.ListByEnv(ctx, e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d tokens, want 2", len(got))
	}
}
