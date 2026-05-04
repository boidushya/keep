package store

import (
	"context"
	"errors"
	"testing"
)

func TestProjectsCreateAndList(t *testing.T) {
	t.Parallel()

	s := Projects{DB: newTestDB(t)}
	ctx := context.Background()

	p1, err := s.Create(ctx, "lyrics-api", "Lyrics API")
	if err != nil {
		t.Fatal(err)
	}
	if p1.ID == 0 || p1.Slug != "lyrics-api" || p1.Name != "Lyrics API" {
		t.Errorf("got %+v", p1)
	}

	p2, err := s.Create(ctx, "blog", "Blog")
	if err != nil {
		t.Fatal(err)
	}

	all, err := s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("got %d projects, want 2", len(all))
	}

	got, err := s.GetBySlug(ctx, "lyrics-api")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != p1.ID {
		t.Error("GetBySlug returned wrong row")
	}

	got2, err := s.Get(ctx, p2.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got2.Slug != "blog" {
		t.Errorf("got %q", got2.Slug)
	}
}

func TestProjectsCreateRejectsDuplicateSlug(t *testing.T) {
	t.Parallel()

	s := Projects{DB: newTestDB(t)}
	ctx := context.Background()

	if _, err := s.Create(ctx, "x", "X"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(ctx, "x", "X2"); err == nil {
		t.Fatal("expected duplicate slug error")
	}
}

func TestProjectsGetMissingReturnsErrNotFound(t *testing.T) {
	t.Parallel()

	s := Projects{DB: newTestDB(t)}
	_, err := s.Get(context.Background(), 999)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestProjectsDelete(t *testing.T) {
	t.Parallel()

	s := Projects{DB: newTestDB(t)}
	ctx := context.Background()

	p, err := s.Create(ctx, "x", "X")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, p.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete, get err = %v", err)
	}
}
