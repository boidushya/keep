// Package auth implements user-side authentication: password hashing, TOTP,
// and signed-cookie sessions.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	pwTime    = 3
	pwMemory  = 64 * 1024
	pwProc    = 4
	pwSaltLen = 16
	pwKeyLen  = 32
)

// HashPassword returns an Argon2id-encoded string in the standard
// $argon2id$v=19$m=...$t=...$p=...$saltB64$hashB64 form.
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("auth: password is empty")
	}

	salt := make([]byte, pwSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: rand salt: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, pwTime, pwMemory, pwProc, pwKeyLen)

	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		pwMemory, pwTime, pwProc,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// VerifyPassword constant-time-compares the encoded hash to one computed from
// password. Returns (true, nil) on match, (false, nil) on mismatch, and an
// error only on malformed input.
func VerifyPassword(encoded, password string) (bool, error) {
	parts := strings.Split(encoded, "$")
	// expected: ["", "argon2id", "v=19", "m=...,t=...,p=...", saltB64, hashB64]
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errors.New("auth: malformed hash")
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, fmt.Errorf("auth: version: %w", err)
	}
	if version != argon2.Version {
		return false, fmt.Errorf("auth: unsupported argon2 version %d", version)
	}

	mem, time, proc, err := parseParams(parts[3])
	if err != nil {
		return false, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("auth: salt: %w", err)
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("auth: hash: %w", err)
	}

	got := argon2.IDKey([]byte(password), salt, time, mem, proc, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

func parseParams(s string) (mem, time uint32, proc uint8, err error) {
	for _, part := range strings.Split(s, ",") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			return 0, 0, 0, fmt.Errorf("auth: bad param %q", part)
		}
		v, perr := strconv.Atoi(kv[1])
		if perr != nil {
			return 0, 0, 0, fmt.Errorf("auth: bad param value %q: %w", kv[1], perr)
		}
		switch kv[0] {
		case "m":
			mem = uint32(v)
		case "t":
			time = uint32(v)
		case "p":
			proc = uint8(v)
		default:
			return 0, 0, 0, fmt.Errorf("auth: unknown param %q", kv[0])
		}
	}
	return mem, time, proc, nil
}
