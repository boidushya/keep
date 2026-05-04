// Package crypto handles master-key derivation and value encryption.
//
// The master password derives a 32-byte symmetric key (Argon2id) that wraps an
// age X25519 identity via ChaCha20-Poly1305. Wrapped form: [12-byte nonce ||
// ciphertext+tag]. The unwrapped age identity then encrypts secret values via
// the standard age framing.
package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	"filippo.io/age"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	saltLen = 16
	keyLen  = 32

	argonTime   = 3
	argonMemory = 64 * 1024 // 64 MiB
	argonProc   = 4
)

// DeriveKey runs Argon2id with fixed (intentionally heavy) parameters. Same
// password and salt always yield the same key.
func DeriveKey(password string, salt []byte) [keyLen]byte {
	out := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonProc, keyLen)
	var k [keyLen]byte
	copy(k[:], out)
	return k
}

// WrapIdentity seals identity under a key derived from password. Returns the
// random salt used for KDF and the sealed bytes (nonce-prefixed ciphertext).
func WrapIdentity(identity *age.X25519Identity, password string) (salt, wrapped []byte, err error) {
	if identity == nil {
		return nil, nil, errors.New("crypto: nil identity")
	}

	salt = make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, fmt.Errorf("rand salt: %w", err)
	}

	key := DeriveKey(password, salt)
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, nil, fmt.Errorf("aead: %w", err)
	}

	wrapped, err = sealWithRandomNonce(aead, []byte(identity.String()))
	if err != nil {
		return nil, nil, err
	}
	return salt, wrapped, nil
}

// UnwrapIdentity reverses WrapIdentity. Returns an error (never panics) on any
// integrity, length, or password failure.
func UnwrapIdentity(wrapped, salt []byte, password string) (*age.X25519Identity, error) {
	if len(salt) != saltLen {
		return nil, fmt.Errorf("crypto: salt len %d, want %d", len(salt), saltLen)
	}
	if len(wrapped) < chacha20poly1305.NonceSize+chacha20poly1305.Overhead {
		return nil, errors.New("crypto: wrapped ciphertext too short")
	}

	key := DeriveKey(password, salt)
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, fmt.Errorf("aead: %w", err)
	}

	nonce, ct := wrapped[:chacha20poly1305.NonceSize], wrapped[chacha20poly1305.NonceSize:]
	plaintext, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: unwrap failed: %w", err)
	}

	id, err := age.ParseX25519Identity(string(plaintext))
	if err != nil {
		return nil, fmt.Errorf("crypto: parse identity: %w", err)
	}
	return id, nil
}

func sealWithRandomNonce(aead cipher.AEAD, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("rand nonce: %w", err)
	}
	out := make([]byte, 0, len(nonce)+len(plaintext)+aead.Overhead())
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, plaintext, nil)
	return out, nil
}
