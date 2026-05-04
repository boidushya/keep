package crypto

import (
	"bytes"
	"testing"

	"filippo.io/age"
)

func TestWrapUnwrapRoundTrip(t *testing.T) {
	t.Parallel()

	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	salt, wrapped, err := WrapIdentity(id, "correct horse battery staple")
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if len(salt) != 16 {
		t.Errorf("salt len = %d, want 16", len(salt))
	}
	if len(wrapped) == 0 {
		t.Fatal("wrapped is empty")
	}

	got, err := UnwrapIdentity(wrapped, salt, "correct horse battery staple")
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if got.String() != id.String() {
		t.Fatal("identity mismatch after unwrap")
	}
}

func TestUnwrapWrongPasswordReturnsError(t *testing.T) {
	t.Parallel()

	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	salt, wrapped, err := WrapIdentity(id, "right")
	if err != nil {
		t.Fatal(err)
	}

	_, err = UnwrapIdentity(wrapped, salt, "wrong")
	if err == nil {
		t.Fatal("expected error for wrong password, got nil")
	}
}

func TestUnwrapTamperedCiphertextReturnsError(t *testing.T) {
	t.Parallel()

	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	salt, wrapped, err := WrapIdentity(id, "pw")
	if err != nil {
		t.Fatal(err)
	}

	tampered := make([]byte, len(wrapped))
	copy(tampered, wrapped)
	tampered[len(tampered)-1] ^= 0x01

	_, err = UnwrapIdentity(tampered, salt, "pw")
	if err == nil {
		t.Fatal("expected error for tampered ciphertext, got nil")
	}
}

func TestUnwrapTooShortReturnsError(t *testing.T) {
	t.Parallel()

	_, err := UnwrapIdentity([]byte{0x00}, make([]byte, 16), "pw")
	if err == nil {
		t.Fatal("expected error for too-short input, got nil")
	}
}

func TestDeriveKeyDeterministic(t *testing.T) {
	t.Parallel()

	salt := bytes.Repeat([]byte{0x01}, 16)
	a := DeriveKey("pw", salt)
	b := DeriveKey("pw", salt)
	if a != b {
		t.Fatal("DeriveKey not deterministic for same input")
	}

	c := DeriveKey("pw2", salt)
	if a == c {
		t.Fatal("DeriveKey collided across passwords")
	}
}
