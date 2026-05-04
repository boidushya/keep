package server

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

// TestSetupVerifyRejectsRecoveryCode is the load-bearing assertion for the
// "TOTP confirm" gate: even though recovery codes work for /login/recovery,
// they MUST NOT satisfy the post-setup TOTP confirmation step.
func TestSetupVerifyRejectsRecoveryCode(t *testing.T) {
	t.Parallel()

	h := newAuthHarness(t)
	h.postForm("/setup", url.Values{
		"password":         {"pw"},
		"password_confirm": {"pw"},
	}).Body.Close()

	codes := h.readRecoveryCodes()
	if len(codes) == 0 {
		t.Fatal("expected recovery codes after setup")
	}

	resp := h.postForm("/setup/verify", url.Values{"totp": {codes[0]}})
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "did not match") {
		t.Fatalf("recovery code should not satisfy verify gate: %s", body)
	}

	user, err := h.deps.Stores.Users.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if user.TOTPVerified {
		t.Fatal("recovery code somehow flipped totp_verified to true")
	}
}

func TestSetupVerifyRejectsBadCode(t *testing.T) {
	t.Parallel()

	h := newAuthHarness(t)
	h.postForm("/setup", url.Values{
		"password":         {"pw"},
		"password_confirm": {"pw"},
	}).Body.Close()

	resp := h.postForm("/setup/verify", url.Values{"totp": {"000000"}})
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "did not match") {
		t.Fatalf("bad code should be rejected: %s", body)
	}
}

func TestSetupVerifyAcceptsCorrectCode(t *testing.T) {
	t.Parallel()

	h := newAuthHarness(t)
	h.postForm("/setup", url.Values{
		"password":         {"pw"},
		"password_confirm": {"pw"},
	}).Body.Close()

	secret := h.readTOTPSecret()
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	resp := h.postForm("/setup/verify", url.Values{"totp": {code}})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/" {
		t.Fatalf("location = %q, want /", loc)
	}

	user, err := h.deps.Stores.Users.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !user.TOTPVerified {
		t.Fatal("totp_verified should be true after a successful confirm")
	}
}

func TestUnverifiedUserGetsRedirectedToVerify(t *testing.T) {
	t.Parallel()

	h := newAuthHarness(t)
	h.postForm("/setup", url.Values{
		"password":         {"pw"},
		"password_confirm": {"pw"},
	}).Body.Close()

	// Try to land on the dashboard before confirming TOTP.
	resp := h.get("/")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want redirect", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/setup/verify" {
		t.Fatalf("location = %q, want /setup/verify", loc)
	}
}

func TestSetupVerifyGetReshowsPageWithoutRecoveryCodes(t *testing.T) {
	t.Parallel()

	h := newAuthHarness(t)
	h.postForm("/setup", url.Values{
		"password":         {"pw"},
		"password_confirm": {"pw"},
	}).Body.Close()

	resp := h.get("/setup/verify")
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	codes := h.readRecoveryCodes()
	for _, c := range codes {
		if strings.Contains(string(body), c) {
			t.Fatalf("recovery code %q leaked on /setup/verify GET", c)
		}
	}
	if !strings.Contains(string(body), "Confirm and continue") {
		t.Fatalf("expected verify form, got: %s", body)
	}
}
