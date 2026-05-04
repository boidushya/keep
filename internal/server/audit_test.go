package server

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestAuditPageShowsRecentActions(t *testing.T) {
	t.Parallel()

	h := setupAuthedWithProject(t)
	h.postForm("/projects/app/envs/prod/secrets", url.Values{
		"key": {"K"}, "value": {"v"},
	}).Body.Close()

	resp := h.get("/audit")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	for _, want := range []string{"login.success", "secret.create"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("missing %q in audit page", want)
		}
	}
}

func TestAuditFilterByAction(t *testing.T) {
	t.Parallel()

	h := setupAuthedWithProject(t)
	h.postForm("/projects/app/envs/prod/secrets", url.Values{
		"key": {"K"}, "value": {"v"},
	}).Body.Close()

	resp := h.get("/audit?action=secret.")
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "secret.create") {
		t.Errorf("expected secret.create on filtered page")
	}
	if strings.Contains(string(body), "login.success") {
		t.Errorf("login.success should be filtered out")
	}
}
