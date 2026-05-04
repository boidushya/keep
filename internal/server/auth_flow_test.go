package server

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/boidushya/keep/internal/auth"
	"github.com/boidushya/keep/internal/crypto"
	keepdb "github.com/boidushya/keep/internal/db"
	"github.com/boidushya/keep/internal/ui"
)

// authHarness wires the full server with templates so the setup/login flow
// can be exercised end-to-end through HTTP.
type authHarness struct {
	t      *testing.T
	srv    *httptest.Server
	deps   Deps
	db     *sql.DB
	client *http.Client
	now    time.Time
}

func newAuthHarness(t *testing.T, opts ...func(*Deps)) *authHarness {
	t.Helper()

	d, err := keepdb.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	if err := keepdb.Migrate(context.Background(), d); err != nil {
		t.Fatal(err)
	}

	tt, err := ui.New()
	if err != nil {
		t.Fatal(err)
	}

	now := time.Unix(1_700_000_000, 0)
	deps := Deps{
		DB:        d,
		Vault:     NewVault(),
		Now:       func() time.Time { return now },
		PublicURL: "http://localhost:4339",
		Stores:    NewStores(d, func() time.Time { return now }),
		Templates: tt,
	}
	for _, opt := range opts {
		opt(&deps)
	}

	srv := httptest.NewServer(New(deps))
	t.Cleanup(srv.Close)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &authHarness{t: t, srv: srv, deps: deps, db: d, client: client, now: now}
}

// readTOTPSecret pulls the encrypted TOTP secret from the DB and decrypts it
// with the in-memory identity. Tests use this to compute valid codes without
// scraping the response.
func (h *authHarness) readTOTPSecret() string {
	h.t.Helper()
	user, err := h.deps.Stores.Users.Get(context.Background())
	if err != nil {
		h.t.Fatal(err)
	}
	id := h.deps.Vault.Identity()
	if id == nil {
		h.t.Fatal("vault sealed; cannot decrypt TOTP secret")
	}
	plain, err := crypto.Decrypt(id, user.TotpSecretEncrypted)
	if err != nil {
		h.t.Fatal(err)
	}
	return string(plain)
}

// readRecoveryCodes pulls the encrypted recovery code list from the DB and
// decrypts it with the in-memory identity.
func (h *authHarness) readRecoveryCodes() []string {
	h.t.Helper()
	user, err := h.deps.Stores.Users.Get(context.Background())
	if err != nil {
		h.t.Fatal(err)
	}
	id := h.deps.Vault.Identity()
	if id == nil {
		h.t.Fatal("vault sealed; cannot decrypt recovery codes")
	}
	codesJSON, err := crypto.Decrypt(id, user.RecoveryCodesEncrypted)
	if err != nil {
		h.t.Fatal(err)
	}
	codes, err := auth.UnmarshalRecoveryCodes(codesJSON)
	if err != nil {
		h.t.Fatal(err)
	}
	return codes
}

func (h *authHarness) postForm(path string, form url.Values) *http.Response {
	h.t.Helper()
	resp, err := h.client.PostForm(h.srv.URL+path, form)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp
}

func (h *authHarness) get(path string) *http.Response {
	h.t.Helper()
	resp, err := h.client.Get(h.srv.URL + path)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp
}

func TestSetupCreatesUserAndUnlocksVault(t *testing.T) {
	t.Parallel()

	h := newAuthHarness(t)
	resp := h.postForm("/setup", url.Values{
		"password":         {"correct horse"},
		"password_confirm": {"correct horse"},
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("setup status = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Confirm your authenticator") {
		t.Fatalf("setup body unexpected: %s", body)
	}

	if h.deps.Vault.IsSealed() {
		t.Fatal("vault should be unlocked after /setup")
	}

	// Recovery codes were stored.
	codes := h.readRecoveryCodes()
	if len(codes) != recoveryCodeCount {
		t.Fatalf("got %d recovery codes, want %d", len(codes), recoveryCodeCount)
	}
}

func TestSetupRejectsMismatchedPasswords(t *testing.T) {
	t.Parallel()

	h := newAuthHarness(t)
	resp := h.postForm("/setup", url.Values{
		"password":         {"a"},
		"password_confirm": {"b"},
	})
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Passwords did not match") {
		t.Fatalf("body: %s", body)
	}
	if !h.deps.Vault.IsSealed() {
		t.Fatal("vault should remain sealed on validation error")
	}
}

func TestSetupSecondCallRedirectsToLogin(t *testing.T) {
	t.Parallel()

	h := newAuthHarness(t)
	first := h.postForm("/setup", url.Values{
		"password":         {"pw"},
		"password_confirm": {"pw"},
	})
	first.Body.Close()

	resp := h.get("/setup")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/login" {
		t.Fatalf("location = %q", loc)
	}
}

func TestLoginGetRedirectsToSetupWhenNoUser(t *testing.T) {
	t.Parallel()

	h := newAuthHarness(t)
	resp := h.get("/login")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/setup" {
		t.Fatalf("location = %q", loc)
	}
}

func TestLoginRejectsWrongPassword(t *testing.T) {
	t.Parallel()

	h := newAuthHarness(t)
	h.postForm("/setup", url.Values{
		"password":         {"pw"},
		"password_confirm": {"pw"},
	}).Body.Close()

	// Issue cookie clear to drop setup session.
	h.deps.Vault.Lock()
	h.client.Jar, _ = cookiejar.New(nil)

	resp := h.postForm("/login", url.Values{
		"password": {"wrong"},
		"totp":     {"000000"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if !h.deps.Vault.IsSealed() {
		t.Fatal("vault should still be sealed")
	}
}

func TestLoginWrongTOTPRejected(t *testing.T) {
	t.Parallel()

	h := newAuthHarness(t)
	h.postForm("/setup", url.Values{
		"password":         {"pw"},
		"password_confirm": {"pw"},
	}).Body.Close()

	secret := h.readTOTPSecret() // need vault unlocked; works because /setup unlocked it

	h.deps.Vault.Lock()
	h.client.Jar, _ = cookiejar.New(nil)

	resp := h.postForm("/login", url.Values{
		"password": {"pw"},
		"totp":     {"000000"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if !h.deps.Vault.IsSealed() {
		t.Fatal("vault should be sealed after bad TOTP")
	}
	_ = secret
}

func TestLoginHappyPathUnlocksVault(t *testing.T) {
	t.Parallel()

	h := newAuthHarness(t)
	h.postForm("/setup", url.Values{
		"password":         {"pw"},
		"password_confirm": {"pw"},
	}).Body.Close()

	secret := h.readTOTPSecret()

	h.deps.Vault.Lock()
	h.client.Jar, _ = cookiejar.New(nil)

	// totp.Validate uses time.Now() internally, so we generate against real
	// time even though the rest of the server runs on the harness clock.
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp := h.postForm("/login", url.Values{
		"password": {"pw"},
		"totp":     {code},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d body=%s", resp.StatusCode, body)
	}
	if h.deps.Vault.IsSealed() {
		t.Fatal("vault should be unlocked after good login")
	}
}

func TestLoginRecoveryConsumesCode(t *testing.T) {
	t.Parallel()

	h := newAuthHarness(t)
	h.postForm("/setup", url.Values{
		"password":         {"pw"},
		"password_confirm": {"pw"},
	}).Body.Close()

	codes := h.readRecoveryCodes()

	h.deps.Vault.Lock()
	h.client.Jar, _ = cookiejar.New(nil)

	resp := h.postForm("/login/recovery", url.Values{
		"password":      {"pw"},
		"recovery_code": {codes[0]},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d body=%s", resp.StatusCode, body)
	}

	left := h.readRecoveryCodes()
	if len(left) != len(codes)-1 {
		t.Fatalf("got %d codes after consume, want %d", len(left), len(codes)-1)
	}
	for _, c := range left {
		if c == codes[0] {
			t.Fatal("consumed code is still in list")
		}
	}
}

func TestLogoutClearsCookieKeepsVaultUnlocked(t *testing.T) {
	t.Parallel()

	h := newAuthHarness(t)
	h.postForm("/setup", url.Values{
		"password":         {"pw"},
		"password_confirm": {"pw"},
	}).Body.Close()
	if h.deps.Vault.IsSealed() {
		t.Fatal("vault should be unlocked after setup")
	}

	resp := h.postForm("/logout", url.Values{})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if h.deps.Vault.IsSealed() {
		t.Fatal("logout must NOT seal the vault (agents still need /render)")
	}
}

func TestAdminSealClearsIdentity(t *testing.T) {
	t.Parallel()

	h := newAuthHarness(t)
	h.postForm("/setup", url.Values{
		"password":         {"pw"},
		"password_confirm": {"pw"},
	}).Body.Close()
	if h.deps.Vault.IsSealed() {
		t.Fatal("expected unlocked")
	}

	resp := h.postForm("/admin/seal", url.Values{})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if !h.deps.Vault.IsSealed() {
		t.Fatal("vault must be sealed after /admin/seal")
	}
}
