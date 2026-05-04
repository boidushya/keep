package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"math/big"
)

// RecoveryCodeAlphabet is the set of characters used for generated recovery
// codes. Avoids ambiguous glyphs (0/O, 1/I, l).
const RecoveryCodeAlphabet = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"

const recoveryCodeLen = 8

// GenerateRecoveryCodes returns n random codes, each `recoveryCodeLen` chars
// from RecoveryCodeAlphabet.
func GenerateRecoveryCodes(n int) ([]string, error) {
	out := make([]string, 0, n)
	max := big.NewInt(int64(len(RecoveryCodeAlphabet)))
	for i := 0; i < n; i++ {
		buf := make([]byte, recoveryCodeLen)
		for j := range buf {
			idx, err := rand.Int(rand.Reader, max)
			if err != nil {
				return nil, err
			}
			buf[j] = RecoveryCodeAlphabet[idx.Int64()]
		}
		out = append(out, string(buf))
	}
	return out, nil
}

// MarshalRecoveryCodes serializes codes as JSON for at-rest storage (via
// encryption).
func MarshalRecoveryCodes(codes []string) ([]byte, error) {
	return json.Marshal(codes)
}

// UnmarshalRecoveryCodes is the inverse.
func UnmarshalRecoveryCodes(b []byte) ([]string, error) {
	var out []string
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ConsumeRecoveryCode constant-time-checks for code in codes; if found, returns
// the new list (with the consumed code removed) and true. If no match, returns
// (nil, false). Pure function (does no I/O).
func ConsumeRecoveryCode(codes []string, code string) ([]string, bool) {
	hit := -1
	for i, c := range codes {
		if subtle.ConstantTimeCompare([]byte(c), []byte(code)) == 1 {
			hit = i
		}
	}
	if hit == -1 {
		return nil, false
	}
	out := make([]string, 0, len(codes)-1)
	out = append(out, codes[:hit]...)
	out = append(out, codes[hit+1:]...)
	return out, true
}

// ErrInvalidRecoveryCode is returned by callers when a user-supplied code
// doesn't match any stored code.
var ErrInvalidRecoveryCode = errors.New("auth: invalid recovery code")
