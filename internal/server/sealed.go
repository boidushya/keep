package server

import (
	"crypto/sha256"
	"io"
	"sync"

	"filippo.io/age"
	"golang.org/x/crypto/hkdf"
)

// Vault holds the master age identity in memory after a successful login, plus
// derived secrets that must not survive a reboot (session signing key). Sealed
// = no identity = /render returns 503 and nothing else can be unlocked.
type Vault struct {
	mu         sync.RWMutex
	id         *age.X25519Identity
	sessionKey []byte
}

// NewVault returns a sealed Vault.
func NewVault() *Vault { return &Vault{} }

// Unlock stores the identity and derives the session signing key.
func (v *Vault) Unlock(id *age.X25519Identity) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.id = id
	if id == nil {
		v.sessionKey = nil
		return nil
	}
	key, err := deriveSessionKey(id)
	if err != nil {
		v.id = nil
		return err
	}
	v.sessionKey = key
	return nil
}

// Lock clears the identity and session key. After this, /render returns 503
// and any cookies signed under the previous key are invalid.
func (v *Vault) Lock() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.id = nil
	v.sessionKey = nil
}

// IsSealed reports whether the vault has no identity loaded.
func (v *Vault) IsSealed() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.id == nil
}

// Identity returns the in-memory identity, or nil when sealed.
func (v *Vault) Identity() *age.X25519Identity {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.id
}

// SessionKey returns the HMAC key for signing session cookies. Empty when
// sealed; callers should treat empty as "sealed" and refuse to mint or trust
// sessions.
func (v *Vault) SessionKey() []byte {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.sessionKey == nil {
		return nil
	}
	out := make([]byte, len(v.sessionKey))
	copy(out, v.sessionKey)
	return out
}

func deriveSessionKey(id *age.X25519Identity) ([]byte, error) {
	r := hkdf.New(sha256.New, []byte(id.String()), nil, []byte("keep:session:v1"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}
