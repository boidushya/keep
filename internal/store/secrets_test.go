package store

import (
	"context"
	"errors"
	"testing"
)

func setupEnv(t *testing.T) (*sqliteHarness, Env) {
	t.Helper()
	d := newTestDB(t)
	pr := Projects{DB: d}
	en := Envs{DB: d}
	ctx := context.Background()
	p, err := pr.Create(ctx, "lyrics-api", "Lyrics API")
	if err != nil {
		t.Fatal(err)
	}
	e, err := en.Create(ctx, p.ID, "prod", "Prod")
	if err != nil {
		t.Fatal(err)
	}
	h := &sqliteHarness{
		Secrets: Secrets{DB: d},
	}
	return h, e
}

type sqliteHarness struct {
	Secrets Secrets
}

func TestSecretsUpsertCreatesV1(t *testing.T) {
	t.Parallel()

	h, env := setupEnv(t)
	ctx := context.Background()

	got, err := h.Secrets.Upsert(ctx, env.ID, "K", []byte("v1-cipher"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID == 0 || got.Key != "K" || got.CurrentVersion != 1 {
		t.Errorf("got %+v", got)
	}
	if string(got.ValueEncrypted) != "v1-cipher" {
		t.Error("value not stored verbatim")
	}
}

func TestSecretsUpsertIncrementsVersion(t *testing.T) {
	t.Parallel()

	h, env := setupEnv(t)
	ctx := context.Background()

	if _, err := h.Secrets.Upsert(ctx, env.ID, "K", []byte("v1"), 0); err != nil {
		t.Fatal(err)
	}
	got, err := h.Secrets.Upsert(ctx, env.ID, "K", []byte("v2"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if got.CurrentVersion != 2 {
		t.Fatalf("version = %d, want 2", got.CurrentVersion)
	}

	versions, err := h.Secrets.ListVersions(ctx, got.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 2 {
		t.Fatalf("got %d versions, want 2", len(versions))
	}
	if versions[0].Version != 2 || versions[1].Version != 1 {
		t.Errorf("versions ordered wrong: %+v", versions)
	}
}

func TestSecretsListByEnv(t *testing.T) {
	t.Parallel()

	h, env := setupEnv(t)
	ctx := context.Background()
	for _, k := range []string{"A_KEY", "B_KEY", "C_KEY"} {
		if _, err := h.Secrets.Upsert(ctx, env.ID, k, []byte("v"), 0); err != nil {
			t.Fatal(err)
		}
	}

	all, err := h.Secrets.ListByEnv(ctx, env.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Fatalf("got %d, want 3", len(all))
	}
	keys := []string{all[0].Key, all[1].Key, all[2].Key}
	if keys[0] != "A_KEY" || keys[1] != "B_KEY" || keys[2] != "C_KEY" {
		t.Errorf("ordering wrong: %v", keys)
	}
}

func TestSecretsDeleteCascadesVersions(t *testing.T) {
	t.Parallel()

	h, env := setupEnv(t)
	ctx := context.Background()
	s, _ := h.Secrets.Upsert(ctx, env.ID, "K", []byte("v"), 0)
	if _, err := h.Secrets.Upsert(ctx, env.ID, "K", []byte("v2"), 0); err != nil {
		t.Fatal(err)
	}

	if err := h.Secrets.Delete(ctx, s.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Secrets.Get(ctx, s.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("expected ErrNotFound")
	}
	v, err := h.Secrets.ListVersions(ctx, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 0 {
		t.Fatalf("versions remain after delete: %+v", v)
	}
}

func TestSecretsRestoreVersionCreatesNewVersion(t *testing.T) {
	t.Parallel()

	h, env := setupEnv(t)
	ctx := context.Background()

	s1, _ := h.Secrets.Upsert(ctx, env.ID, "K", []byte("a"), 0)
	if _, err := h.Secrets.Upsert(ctx, env.ID, "K", []byte("b"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Secrets.Upsert(ctx, env.ID, "K", []byte("c"), 0); err != nil {
		t.Fatal(err)
	}

	restored, err := h.Secrets.RestoreVersion(ctx, s1.ID, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if restored.CurrentVersion != 4 {
		t.Fatalf("restored version = %d, want 4", restored.CurrentVersion)
	}
	if string(restored.ValueEncrypted) != "a" {
		t.Errorf("value = %q, want a", restored.ValueEncrypted)
	}

	versions, err := h.Secrets.ListVersions(ctx, s1.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 4 {
		t.Fatalf("got %d versions, want 4", len(versions))
	}
}

func TestSecretsRestoreUnknownVersionErrors(t *testing.T) {
	t.Parallel()

	h, env := setupEnv(t)
	ctx := context.Background()
	s, _ := h.Secrets.Upsert(ctx, env.ID, "K", []byte("a"), 0)

	if _, err := h.Secrets.RestoreVersion(ctx, s.ID, 999, 0); err == nil {
		t.Fatal("expected error for missing version")
	}
}
