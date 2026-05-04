package db

import (
	"context"
	"testing"
)

func TestOpenInMemoryAppliesPragmas(t *testing.T) {
	t.Parallel()

	d, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	ctx := context.Background()

	checks := []struct {
		pragma string
		want   string
	}{
		{"foreign_keys", "1"},
		{"busy_timeout", "5000"},
	}
	for _, c := range checks {
		var got string
		if err := d.QueryRowContext(ctx, "PRAGMA "+c.pragma).Scan(&got); err != nil {
			t.Fatalf("read pragma %s: %v", c.pragma, err)
		}
		if got != c.want {
			t.Errorf("pragma %s = %q, want %q", c.pragma, got, c.want)
		}
	}
}

func TestOpenFileCreatesParentlessFile(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := tmp + "/k.db"

	d, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}
