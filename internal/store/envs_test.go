package store

import (
	"context"
	"errors"
	"testing"
)

func setupProject(t *testing.T) (*Projects, *Envs, Project) {
	t.Helper()
	d := newTestDB(t)
	pr := &Projects{DB: d}
	en := &Envs{DB: d}
	p, err := pr.Create(context.Background(), "lyrics-api", "Lyrics API")
	if err != nil {
		t.Fatal(err)
	}
	return pr, en, p
}

func TestEnvsCreateAndList(t *testing.T) {
	t.Parallel()

	_, en, p := setupProject(t)
	ctx := context.Background()

	prod, err := en.Create(ctx, p.ID, "prod", "Production")
	if err != nil {
		t.Fatal(err)
	}
	staging, err := en.Create(ctx, p.ID, "staging", "Staging")
	if err != nil {
		t.Fatal(err)
	}
	if prod.ID == 0 || staging.ID == 0 {
		t.Fatal("ids not set")
	}

	all, err := en.ListByProject(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("got %d envs, want 2", len(all))
	}
}

func TestEnvsCreateRejectsDuplicateSlugWithinProject(t *testing.T) {
	t.Parallel()

	_, en, p := setupProject(t)
	ctx := context.Background()

	if _, err := en.Create(ctx, p.ID, "prod", "Production"); err != nil {
		t.Fatal(err)
	}
	if _, err := en.Create(ctx, p.ID, "prod", "Prod 2"); err == nil {
		t.Fatal("expected duplicate (project, slug) error")
	}
}

func TestEnvsCreateAllowsSameSlugDifferentProject(t *testing.T) {
	t.Parallel()

	pr, en, p1 := setupProject(t)
	ctx := context.Background()

	p2, err := pr.Create(ctx, "blog", "Blog")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := en.Create(ctx, p1.ID, "prod", "Prod1"); err != nil {
		t.Fatal(err)
	}
	if _, err := en.Create(ctx, p2.ID, "prod", "Prod2"); err != nil {
		t.Fatalf("expected ok, got %v", err)
	}
}

func TestEnvsGetBySlug(t *testing.T) {
	t.Parallel()

	_, en, p := setupProject(t)
	ctx := context.Background()
	prod, _ := en.Create(ctx, p.ID, "prod", "Prod")

	got, err := en.GetBySlug(ctx, p.ID, "prod")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != prod.ID {
		t.Error("wrong env returned")
	}

	if _, err := en.GetBySlug(ctx, p.ID, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestEnvsDelete(t *testing.T) {
	t.Parallel()

	_, en, p := setupProject(t)
	ctx := context.Background()
	prod, _ := en.Create(ctx, p.ID, "prod", "Prod")

	if err := en.Delete(ctx, prod.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := en.Get(ctx, prod.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("expected ErrNotFound after delete")
	}
}
