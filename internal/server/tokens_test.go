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

// setupAuthedWithProject runs setup, creates project "app" + env "prod", and
// returns the harness logged in. PublicURL is set so the agent script renders
// a fully-qualified endpoint.
func setupAuthedWithProject(t *testing.T) *authHarness {
	t.Helper()
	h := newAuthHarness(t, func(d *Deps) {
		d.PublicURL = "https://keep.example.com"
	})
	h.postForm("/setup", url.Values{
		"password":         {"pw"},
		"password_confirm": {"pw"},
	}).Body.Close()

	secret := h.readTOTPSecret()
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	h.postForm("/setup/verify", url.Values{"totp": {code}}).Body.Close()

	h.postForm("/projects", url.Values{
		"slug": {"app"}, "name": {"App"},
	}).Body.Close()
	h.postForm("/projects/app/envs", url.Values{
		"slug": {"prod"}, "name": {"Prod"},
	}).Body.Close()
	return h
}

func TestTokensMintRendersPlaintextOnce(t *testing.T) {
	t.Parallel()

	h := setupAuthedWithProject(t)
	resp := h.postForm("/projects/app/envs/prod/tokens", url.Values{
		"name":          {"hetzner"},
		"expires_in":    {"never"},
		"output":        {"/etc/app.env"},
		"reload_cmd":    {"systemctl restart app"},
		"required_keys": {"K"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Token minted") {
		t.Fatalf("post-mint page expected: %s", body)
	}
	if !strings.Contains(string(body), "TOKEN=") {
		t.Fatalf("agent script not in post-mint page: %s", body)
	}
	if !strings.Contains(string(body), "https://keep.example.com/render") {
		t.Fatalf("endpoint not in script: %s", body)
	}

	// Token row exists.
	toks, err := h.deps.Stores.Tokens.ListByEnv(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(toks) != 1 || toks[0].Name != "hetzner" {
		t.Fatalf("got %+v", toks)
	}
}

func TestTokenScriptDownloadAvailableJustAfterMint(t *testing.T) {
	t.Parallel()

	h := setupAuthedWithProject(t)
	post := h.postForm("/projects/app/envs/prod/tokens", url.Values{
		"name": {"a"},
	})
	post.Body.Close()

	toks, _ := h.deps.Stores.Tokens.ListByEnv(context.Background(), 1)
	if len(toks) != 1 {
		t.Fatalf("expected 1 token")
	}
	id := toks[0].ID

	resp := h.get("/projects/app/envs/prod/tokens/" + intToStr(id) + "/script.sh")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d body=%s", resp.StatusCode, body)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "TOKEN=") {
		t.Fatalf("script body unexpected: %s", body)
	}
	if !strings.Contains(resp.Header.Get("Content-Type"), "shellscript") {
		t.Errorf("content-type = %q", resp.Header.Get("Content-Type"))
	}
}

func TestTokenRevokeBlocksRender(t *testing.T) {
	t.Parallel()

	h := setupAuthedWithProject(t)

	// Need a secret so /render has something to return.
	h.postForm("/projects/app/envs/prod/secrets", url.Values{
		"key": {"K"}, "value": {"v"},
	}).Body.Close()

	post := h.postForm("/projects/app/envs/prod/tokens", url.Values{
		"name": {"a"},
	})
	post.Body.Close()
	toks, _ := h.deps.Stores.Tokens.ListByEnv(context.Background(), 1)
	id := toks[0].ID

	// Pull plaintext from the cache so we can hit /render with it.
	plain, ok := inMemoryTokenCache.get(id)
	if !ok {
		t.Fatal("token plaintext not in cache after mint")
	}

	// Pre-revoke /render should succeed.
	req, _ := http.NewRequest("GET", h.srv.URL+"/render", nil)
	req.Header.Set("Authorization", "Bearer "+plain)
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/render before revoke: status=%d", resp.StatusCode)
	}

	// Revoke.
	rev := h.postForm("/projects/app/envs/prod/tokens/"+intToStr(id)+"/revoke", url.Values{})
	rev.Body.Close()

	req2, _ := http.NewRequest("GET", h.srv.URL+"/render", nil)
	req2.Header.Set("Authorization", "Bearer "+plain)
	resp2, err := h.client.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/render after revoke: status=%d", resp2.StatusCode)
	}
}

func intToStr(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	idx := len(buf)
	for i > 0 {
		idx--
		buf[idx] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		idx--
		buf[idx] = '-'
	}
	return string(buf[idx:])
}
