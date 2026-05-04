package crypto

import (
	"bytes"
	"testing"

	"filippo.io/age"
)

func TestEncryptDecryptRoundTripSizes(t *testing.T) {
	t.Parallel()

	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"single byte", 1},
		{"1KB", 1 << 10},
		{"1MB", 1 << 20},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			plaintext := make([]byte, c.size)
			for i := range plaintext {
				plaintext[i] = byte(i % 251)
			}

			ct, err := Encrypt(id, plaintext)
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			pt, err := Decrypt(id, ct)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if !bytes.Equal(pt, plaintext) {
				t.Fatal("plaintext mismatch")
			}
		})
	}
}

func TestDecryptCorruptedCiphertextReturnsError(t *testing.T) {
	t.Parallel()

	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	ct, err := Encrypt(id, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}

	bad := make([]byte, len(ct))
	copy(bad, ct)
	bad[len(bad)-1] ^= 0xff

	if _, err := Decrypt(id, bad); err == nil {
		t.Fatal("expected error for corrupted ciphertext, got nil")
	}
}

func TestDecryptWithDifferentIdentityFails(t *testing.T) {
	t.Parallel()

	a, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	b, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	ct, err := Encrypt(a, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt(b, ct); err == nil {
		t.Fatal("expected error decrypting with wrong identity, got nil")
	}
}
