package store

import (
	"context"
	"testing"
)

func TestAuditAppendAndList(t *testing.T) {
	t.Parallel()

	a := Audit{DB: newTestDB(t)}
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if err := a.Append(ctx, AuditEntry{
			At:       int64(i + 1),
			Actor:    "user:1",
			Action:   "secret.update",
			Target:   "secrets/1",
			Metadata: `{"key":"X"}`,
		}); err != nil {
			t.Fatal(err)
		}
	}

	got, err := a.List(ctx, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d, want 3", len(got))
	}
	// Newest first by id desc, so the last-inserted comes first.
	if got[0].At != 3 || got[2].At != 1 {
		t.Fatalf("ordering wrong: %+v", got)
	}
}

func TestAuditListPaginatesByBeforeID(t *testing.T) {
	t.Parallel()

	a := Audit{DB: newTestDB(t)}
	ctx := context.Background()
	for i := 1; i <= 5; i++ {
		if err := a.Append(ctx, AuditEntry{
			At:     int64(i),
			Actor:  "user:1",
			Action: "x",
			Target: "y",
		}); err != nil {
			t.Fatal(err)
		}
	}

	first, _ := a.List(ctx, 2, 0)
	if len(first) != 2 {
		t.Fatalf("first page %d", len(first))
	}
	second, _ := a.List(ctx, 2, first[len(first)-1].ID)
	if len(second) != 2 {
		t.Fatalf("second page %d", len(second))
	}
	for _, fst := range first {
		for _, snd := range second {
			if fst.ID == snd.ID {
				t.Fatalf("overlap: id %d in both pages", fst.ID)
			}
		}
	}
}
