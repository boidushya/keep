package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestSetupReturnsScannableSecretAndQR(t *testing.T) {
	t.Parallel()

	secret, qr, err := SetupTOTP("keep", "test@example.com")
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if secret == "" {
		t.Fatal("empty secret")
	}
	if !strings.HasPrefix(string(qr), "\x89PNG") {
		t.Fatal("qr should be a PNG")
	}

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !VerifyTOTP(secret, code) {
		t.Fatal("VerifyTOTP failed for code we just generated")
	}
}

func TestVerifyTOTPRejectsWrongCode(t *testing.T) {
	t.Parallel()

	secret, _, err := SetupTOTP("keep", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if VerifyTOTP(secret, "000000") {
		t.Fatal("000000 should not verify")
	}
}

func TestVerifyTOTPMalformedCodeReturnsFalse(t *testing.T) {
	t.Parallel()

	secret, _, err := SetupTOTP("keep", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if VerifyTOTP(secret, "abcdef") {
		t.Fatal("non-numeric code must not verify")
	}
}
