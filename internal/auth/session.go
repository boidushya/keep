package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// SessionMaxAge is how long a signed session token remains valid.
const SessionMaxAge = 30 * 24 * 60 * 60 // 30 days, in seconds

// Session is the payload encoded into the signed session token.
type Session struct {
	UserID   int
	IssuedAt int64
}

// EncodeSession returns a signed token of the form "<payloadB64>.<sigB64>".
// payloadB64 is base64url("<userID>|<issuedAt>"); sig is HMAC-SHA256 over the
// payload (raw bytes, not base64).
func EncodeSession(s Session, key []byte) string {
	payload := []byte(strconv.Itoa(s.UserID) + "|" + strconv.FormatInt(s.IssuedAt, 10))
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	sig := mac.Sum(nil)

	enc := base64.RawURLEncoding
	return enc.EncodeToString(payload) + "." + enc.EncodeToString(sig)
}

// DecodeSession parses, verifies HMAC, and checks expiry against now (Unix
// seconds).
func DecodeSession(token string, key []byte, now int64) (Session, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return Session{}, errors.New("auth: malformed session token")
	}

	enc := base64.RawURLEncoding
	payload, err := enc.DecodeString(parts[0])
	if err != nil {
		return Session{}, fmt.Errorf("auth: payload decode: %w", err)
	}
	sig, err := enc.DecodeString(parts[1])
	if err != nil {
		return Session{}, fmt.Errorf("auth: sig decode: %w", err)
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	want := mac.Sum(nil)
	if !hmac.Equal(want, sig) {
		return Session{}, errors.New("auth: bad signature")
	}

	fields := strings.Split(string(payload), "|")
	if len(fields) != 2 {
		return Session{}, errors.New("auth: bad payload")
	}
	uid, err := strconv.Atoi(fields[0])
	if err != nil {
		return Session{}, fmt.Errorf("auth: user id: %w", err)
	}
	issued, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return Session{}, fmt.Errorf("auth: issued at: %w", err)
	}
	if now-issued > SessionMaxAge {
		return Session{}, errors.New("auth: session expired")
	}
	if issued > now+60 {
		return Session{}, errors.New("auth: session issued in the future")
	}

	return Session{UserID: uid, IssuedAt: issued}, nil
}
