package server

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestBulkImportCreatesAllEntries(t *testing.T) {
	t.Parallel()

	h := setupAuthedWithProject(t)

	resp := h.postForm("/projects/app/envs/prod/secrets/bulk", url.Values{
		"env": {"DATABASE_URL=postgres://x\nJWT_SECRET=hush\n# comment\nREDIS_URL=redis://r\n"},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	page := h.get("/projects/app?env=prod")
	defer page.Body.Close()
	body, _ := io.ReadAll(page.Body)
	for _, want := range []string{"DATABASE_URL", "JWT_SECRET", "REDIS_URL"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("missing %q in page", want)
		}
	}
}

func TestBulkImportRejectsBadInput(t *testing.T) {
	t.Parallel()

	h := setupAuthedWithProject(t)
	resp := h.postForm("/projects/app/envs/prod/secrets/bulk", url.Values{
		"env": {"this is not an env file"},
	})
	resp.Body.Close()
	if resp.Header.Get("Location") == "" || !strings.Contains(resp.Header.Get("Location"), "error=bulk") {
		t.Fatalf("expected redirect with error=bulk, got %q", resp.Header.Get("Location"))
	}
}

func TestEnvDeleteRequiresSlugConfirm(t *testing.T) {
	t.Parallel()

	h := setupAuthedWithProject(t)
	resp := h.postForm("/projects/app/envs/prod/delete", url.Values{
		"confirm": {"wrong"},
	})
	resp.Body.Close()
	if !strings.Contains(resp.Header.Get("Location"), "error=confirm") {
		t.Fatalf("expected confirm error redirect, got %q", resp.Header.Get("Location"))
	}

	envs, _ := h.deps.Stores.Envs.ListByProject(context.Background(), 1)
	if len(envs) != 1 {
		t.Fatal("env should not be deleted on bad confirm")
	}
}

func TestEnvDeleteWithCorrectConfirmRemovesEnv(t *testing.T) {
	t.Parallel()

	h := setupAuthedWithProject(t)
	h.postForm("/projects/app/envs/prod/secrets", url.Values{
		"key": {"K"}, "value": {"v"},
	}).Body.Close()

	resp := h.postForm("/projects/app/envs/prod/delete", url.Values{
		"confirm": {"prod"},
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	envs, _ := h.deps.Stores.Envs.ListByProject(context.Background(), 1)
	if len(envs) != 0 {
		t.Fatalf("env should be deleted, got %d", len(envs))
	}
}

func TestSecretEditPageRevealsValue(t *testing.T) {
	t.Parallel()

	h := setupAuthedWithProject(t)
	h.postForm("/projects/app/envs/prod/secrets", url.Values{
		"key": {"DB_URL"}, "value": {"postgres://localtest"},
	}).Body.Close()

	resp := h.get("/projects/app/envs/prod/secrets/DB_URL/edit")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "postgres://localtest") {
		t.Fatalf("edit page did not reveal current value: %s", body)
	}
}

func TestProjectPageHidesTokensButtonWithNoEnv(t *testing.T) {
	t.Parallel()

	h := setupAuthed(t)
	h.postForm("/projects", url.Values{
		"slug": {"empty"}, "name": {"Empty"},
	}).Body.Close()

	resp := h.get("/projects/empty")
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "/envs//tokens") {
		t.Fatal("Tokens button should not link to /envs//tokens when no env exists")
	}
	if strings.Contains(string(body), "Tokens</a>") {
		t.Fatal("Tokens button should be hidden when no env exists")
	}
}
