package crypto

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"filippo.io/age"
)

// Encrypt encrypts plaintext to identity's recipient using age. Output is the
// raw age binary stream (no armor).
func Encrypt(identity *age.X25519Identity, plaintext []byte) ([]byte, error) {
	if identity == nil {
		return nil, errors.New("crypto: nil identity")
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, identity.Recipient())
	if err != nil {
		return nil, fmt.Errorf("age encrypt: %w", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("age write: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("age close: %w", err)
	}
	return buf.Bytes(), nil
}

// Decrypt decrypts ciphertext using identity. Returns an error on any framing
// or AEAD failure.
func Decrypt(identity *age.X25519Identity, ciphertext []byte) ([]byte, error) {
	if identity == nil {
		return nil, errors.New("crypto: nil identity")
	}
	r, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err != nil {
		return nil, fmt.Errorf("age decrypt: %w", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("age read: %w", err)
	}
	return out, nil
}
