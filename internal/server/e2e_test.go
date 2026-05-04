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

// TestE2EHappyPath walks the full lifecycle through the HTTP layer:
// setup -> create project + env -> add secrets -> mint token -> /render ->
// update a secret -> /render -> seal -> /render returns 503 -> log back in ->
// /render works again.
func TestE2EHappyPath(t *testing.T) {
	t.Parallel()

	h := newAuthHarness(t, func(d *Deps) {
		d.PublicURL = "https://keep.test"
	})

	// 1. Setup creates the user, unlocks the vault, drops a session cookie.
	resp := h.postForm("/setup", url.Values{
		"password":         {"strong-password"},
		"password_confirm": {"strong-password"},
	})
	resp.Body.Close()
	if h.deps.Vault.IsSealed() {
		t.Fatal("vault should be unlocked after setup")
	}

	totpSecret := h.readTOTPSecret()

	// 1a. Confirm TOTP setup (otherwise all app routes redirect to /setup/verify).
	confirmCode, err := totp.GenerateCode(totpSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	verify := h.postForm("/setup/verify", url.Values{"totp": {confirmCode}})
	verify.Body.Close()
	if verify.StatusCode != http.StatusSeeOther {
		t.Fatalf("/setup/verify status = %d", verify.StatusCode)
	}

	// 2. Project + env.
	r := h.postForm("/projects", url.Values{
		"slug": {"lyrics-api"}, "name": {"Lyrics API"},
	})
	r.Body.Close()
	r = h.postForm("/projects/lyrics-api/envs", url.Values{
		"slug": {"prod"}, "name": {"Prod"},
	})
	r.Body.Close()

	// 3. Three secrets.
	for _, kv := range [][2]string{
		{"DATABASE_URL", "postgres://primary"},
		{"JWT_SECRET", "supersecret"},
		{"REDIS_URL", "redis://cache"},
	} {
		r := h.postForm("/projects/lyrics-api/envs/prod/secrets", url.Values{
			"key": {kv[0]}, "value": {kv[1]},
		})
		r.Body.Close()
	}

	// 4. Mint a token. The plaintext is in the in-memory cache.
	r = h.postForm("/projects/lyrics-api/envs/prod/tokens", url.Values{
		"name": {"hetzner"},
	})
	r.Body.Close()

	toks, err := h.deps.Stores.Tokens.ListByEnv(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(toks) != 1 {
		t.Fatalf("got %d tokens", len(toks))
	}
	plain, ok := inMemoryTokenCache.get(toks[0].ID)
	if !ok {
		t.Fatal("plaintext missing from cache after mint")
	}

	// 5. /render returns the three secrets.
	body := mustRender(t, h, plain)
	want := "DATABASE_URL=postgres://primary\nJWT_SECRET=supersecret\nREDIS_URL=redis://cache\n"
	if body != want {
		t.Fatalf("/render body =\n%s\nwant\n%s", body, want)
	}

	// 6. Update DATABASE_URL.
	r = h.postForm("/projects/lyrics-api/envs/prod/secrets/DATABASE_URL", url.Values{
		"op":    {"update"},
		"value": {"postgres://replica"},
	})
	r.Body.Close()

	body2 := mustRender(t, h, plain)
	if !strings.Contains(body2, "DATABASE_URL=postgres://replica\n") {
		t.Fatalf("update did not propagate to /render: %q", body2)
	}

	// 7. Seal.
	r = h.postForm("/admin/seal", url.Values{})
	r.Body.Close()
	if !h.deps.Vault.IsSealed() {
		t.Fatal("vault should be sealed after /admin/seal")
	}
	status, _ := getRender(t, h, plain)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("/render after seal: status=%d, want 503", status)
	}

	// 8. Re-login. TOTP comes from the secret we cached BEFORE sealing
	// (decryption needed the unlocked identity then).
	code, err := totp.GenerateCode(totpSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	r = h.postForm("/login", url.Values{
		"password": {"strong-password"},
		"totp":     {code},
	})
	r.Body.Close()
	if h.deps.Vault.IsSealed() {
		t.Fatal("vault should be unlocked after second login")
	}

	body3 := mustRender(t, h, plain)
	if !strings.Contains(body3, "JWT_SECRET=supersecret") {
		t.Fatalf("/render after re-login lost a secret: %q", body3)
	}
}

func mustRender(t *testing.T, h *authHarness, plaintext string) string {
	t.Helper()
	status, body := getRender(t, h, plaintext)
	if status != http.StatusOK {
		t.Fatalf("/render status=%d body=%q", status, body)
	}
	return body
}

func getRender(t *testing.T, h *authHarness, plaintext string) (int, string) {
	t.Helper()
	req, err := http.NewRequest("GET", h.srv.URL+"/render", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+plaintext)
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}
