package auth

import (
	"strings"
	"testing"
	"time"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

func TestSessionRoundTrip(t *testing.T) {
	t.Parallel()

	now := time.Now().Unix()
	s := Session{UserID: 1, IssuedAt: now}
	tok := EncodeSession(s, testKey)

	got, err := DecodeSession(tok, testKey, now)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.UserID != 1 || got.IssuedAt != now {
		t.Fatalf("got %+v want %+v", got, s)
	}
}

func TestSessionRejectsTamperedSignature(t *testing.T) {
	t.Parallel()

	s := Session{UserID: 1, IssuedAt: time.Now().Unix()}
	tok := EncodeSession(s, testKey)

	tampered := flipLastByte(tok)
	if _, err := DecodeSession(tampered, testKey, time.Now().Unix()); err == nil {
		t.Fatal("expected error for tampered token")
	}
}

func TestSessionRejectsWrongKey(t *testing.T) {
	t.Parallel()

	s := Session{UserID: 1, IssuedAt: time.Now().Unix()}
	tok := EncodeSession(s, testKey)

	otherKey := []byte("ffffffffffffffffffffffffffffffff")
	if _, err := DecodeSession(tok, otherKey, time.Now().Unix()); err == nil {
		t.Fatal("expected error for wrong key")
	}
}

func TestSessionRejectsExpired(t *testing.T) {
	t.Parallel()

	issued := time.Now().Add(-31 * 24 * time.Hour).Unix()
	s := Session{UserID: 1, IssuedAt: issued}
	tok := EncodeSession(s, testKey)

	if _, err := DecodeSession(tok, testKey, time.Now().Unix()); err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestSessionRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	for _, s := range []string{"", "abc", "no.dot", "x.y.z"} {
		if _, err := DecodeSession(s, testKey, time.Now().Unix()); err == nil {
			t.Errorf("expected error for malformed %q", s)
		}
	}
}

func flipLastByte(s string) string {
	if s == "" {
		return s
	}
	last := s[len(s)-1]
	if last == 'A' {
		last = 'B'
	} else {
		last = 'A'
	}
	return strings.TrimRight(s, string(s[len(s)-1])) + string(last)
}
