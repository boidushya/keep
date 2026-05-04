package server

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

// setupAuthed runs through the full first-run flow: POST /setup creates the
// user, then POST /setup/verify confirms the TOTP setup. The returned harness
// is fully authenticated and able to access protected pages.
func setupAuthed(t *testing.T) *authHarness {
	t.Helper()
	h := newAuthHarness(t)
	resp := h.postForm("/setup", url.Values{
		"password":         {"pw"},
		"password_confirm": {"pw"},
	})
	resp.Body.Close()

	secret := h.readTOTPSecret()
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	verify := h.postForm("/setup/verify", url.Values{"totp": {code}})
	verify.Body.Close()
	if verify.StatusCode != http.StatusSeeOther {
		t.Fatalf("/setup/verify status = %d", verify.StatusCode)
	}
	return h
}

func TestDashboardEmptyShowsNoProjectsYet(t *testing.T) {
	t.Parallel()

	h := setupAuthed(t)
	resp := h.get("/")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "No projects yet") {
		t.Fatalf("body did not contain empty state: %s", body)
	}
}

func TestProjectCreateRedirectsToProjectPage(t *testing.T) {
	t.Parallel()

	h := setupAuthed(t)
	resp := h.postForm("/projects", url.Values{
		"slug": {"lyrics-api"},
		"name": {"Lyrics API"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/projects/lyrics-api" {
		t.Fatalf("location = %q", loc)
	}
}

func TestProjectCreateRejectsBadSlug(t *testing.T) {
	t.Parallel()

	h := setupAuthed(t)
	resp := h.postForm("/projects", url.Values{
		"slug": {"NOT_OK"},
		"name": {"X"},
	})
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "lowercase letters") {
		t.Fatalf("body should show validation error: %s", body)
	}
}

func TestEnvCreateAndSecretLifecycle(t *testing.T) {
	t.Parallel()

	h := setupAuthed(t)
	h.postForm("/projects", url.Values{
		"slug": {"app"}, "name": {"App"},
	}).Body.Close()

	h.postForm("/projects/app/envs", url.Values{
		"slug": {"prod"}, "name": {"Prod"},
	}).Body.Close()

	// Create a secret.
	resp := h.postForm("/projects/app/envs/prod/secrets", url.Values{
		"key": {"DATABASE_URL"}, "value": {"postgres://x"},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("create status = %d", resp.StatusCode)
	}

	// Project page shows the secret.
	page := h.get("/projects/app?env=prod")
	defer page.Body.Close()
	body, _ := io.ReadAll(page.Body)
	if !strings.Contains(string(body), "DATABASE_URL") {
		t.Fatalf("secret not on page: %s", body)
	}
	if !strings.Contains(string(body), `data-value="postgres://x"`) {
		t.Fatalf("decrypted value not in data attr: %s", body)
	}

	// Update.
	upd := h.postForm("/projects/app/envs/prod/secrets/DATABASE_URL", url.Values{
		"op":    {"update"},
		"value": {"postgres://y"},
	})
	upd.Body.Close()

	page2 := h.get("/projects/app?env=prod")
	defer page2.Body.Close()
	body2, _ := io.ReadAll(page2.Body)
	if !strings.Contains(string(body2), `data-value="postgres://y"`) {
		t.Fatalf("update did not persist: %s", body2)
	}
	if !strings.Contains(string(body2), `v2`) {
		t.Fatalf("version did not bump to v2: %s", body2)
	}

	// History page lists 2 versions.
	hist := h.get("/projects/app/envs/prod/secrets/DATABASE_URL/versions")
	defer hist.Body.Close()
	hbody, _ := io.ReadAll(hist.Body)
	if !strings.Contains(string(hbody), "v1") || !strings.Contains(string(hbody), "v2") {
		t.Fatalf("history missing versions: %s", hbody)
	}
	if !strings.Contains(string(hbody), "postgres://x") {
		t.Fatalf("history missing v1 plaintext: %s", hbody)
	}

	// Restore v1.
	rest := h.postForm("/projects/app/envs/prod/secrets/DATABASE_URL/versions/1/restore", url.Values{})
	rest.Body.Close()
	page3 := h.get("/projects/app?env=prod")
	defer page3.Body.Close()
	body3, _ := io.ReadAll(page3.Body)
	if !strings.Contains(string(body3), `data-value="postgres://x"`) {
		t.Fatalf("restore did not bring back v1: %s", body3)
	}

	// Delete.
	del := h.postForm("/projects/app/envs/prod/secrets/DATABASE_URL", url.Values{
		"op": {"delete"},
	})
	del.Body.Close()
	page4 := h.get("/projects/app?env=prod")
	defer page4.Body.Close()
	body4, _ := io.ReadAll(page4.Body)
	if !strings.Contains(string(body4), "0 secrets") {
		t.Fatalf("expected '0 secrets' after delete: %s", body4)
	}
}

func TestUnauthenticatedAccessRedirects(t *testing.T) {
	t.Parallel()

	h := newAuthHarness(t)
	// no setup, no session, no vault unlock.

	resp := h.get("/projects/anything")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if resp.Header.Get("Location") != "/login" {
		t.Fatalf("loc = %q", resp.Header.Get("Location"))
	}
}
