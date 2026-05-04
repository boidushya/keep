package server

import "testing"

func TestParseDotenvBasic(t *testing.T) {
	t.Parallel()
	got, err := parseDotenv(`A=1
B=two
# comment
C="three with space"
D='single'

`)
	if err != nil {
		t.Fatal(err)
	}
	want := []dotenvEntry{
		{"A", "1"}, {"B", "two"}, {"C", "three with space"}, {"D", "single"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("entry %d: got %+v want %+v", i, got[i], want[i])
		}
	}
}

func TestParseDotenvRejectsBadKey(t *testing.T) {
	t.Parallel()
	if _, err := parseDotenv(`9NOPE=x`); err == nil {
		t.Fatal("expected rejection of leading-digit key")
	}
}

func TestParseDotenvRejectsMissingEq(t *testing.T) {
	t.Parallel()
	if _, err := parseDotenv(`KEY only`); err == nil {
		t.Fatal("expected rejection of line without =")
	}
}

func TestParseDotenvRejectsEmpty(t *testing.T) {
	t.Parallel()
	if _, err := parseDotenv(``); err == nil {
		t.Fatal("expected error for empty input")
	}
	if _, err := parseDotenv("# only comments\n\n"); err == nil {
		t.Fatal("expected error when no entries")
	}
}
