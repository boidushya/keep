package auth

import (
	"strings"
	"testing"
)

func TestHashAndVerifyHappyPath(t *testing.T) {
	t.Parallel()

	h, err := HashPassword("correct horse")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if !strings.HasPrefix(h, "$argon2id$") {
		t.Fatalf("hash format unexpected: %q", h)
	}

	ok, err := VerifyPassword(h, "correct horse")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("verify should succeed for correct password")
	}
}

func TestVerifyRejectsWrongPassword(t *testing.T) {
	t.Parallel()

	h, err := HashPassword("right")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyPassword(h, "wrong")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("verify should fail for wrong password")
	}
}

func TestHashRejectsEmptyPassword(t *testing.T) {
	t.Parallel()

	if _, err := HashPassword(""); err == nil {
		t.Fatal("expected error for empty password")
	}
}

func TestVerifyRejectsTamperedHash(t *testing.T) {
	t.Parallel()

	h, err := HashPassword("pw")
	if err != nil {
		t.Fatal(err)
	}
	tampered := h[:len(h)-1] + "X"
	ok, _ := VerifyPassword(tampered, "pw")
	if ok {
		t.Fatal("tampered hash should not verify")
	}
}

func TestHashesAreUniqueForSamePassword(t *testing.T) {
	t.Parallel()

	a, _ := HashPassword("same")
	b, _ := HashPassword("same")
	if a == b {
		t.Fatal("two hashes of the same password should differ (random salt)")
	}
}
