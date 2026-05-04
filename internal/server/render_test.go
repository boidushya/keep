package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/boidushya/keep/internal/crypto"
	keepdb "github.com/boidushya/keep/internal/db"
	"github.com/boidushya/keep/internal/store"
)

type harness struct {
	server   *httptest.Server
	deps     Deps
	identity *age.X25519Identity
	project  store.Project
	env      store.Env
	token    string
}

func newRenderHarness(t *testing.T) *harness {
	t.Helper()

	d, err := keepdb.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	if err := keepdb.Migrate(context.Background(), d); err != nil {
		t.Fatal(err)
	}

	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	v := NewVault()
	if err := v.Unlock(id); err != nil {
		t.Fatal(err)
	}

	deps := Deps{
		DB:     d,
		Vault:  v,
		Now:    func() time.Time { return time.Unix(1_700_000_000, 0) },
		Stores: NewStores(d, func() time.Time { return time.Unix(1_700_000_000, 0) }),
	}

	srv := httptest.NewServer(New(deps))
	t.Cleanup(srv.Close)

	ctx := context.Background()
	p, err := deps.Stores.Projects.Create(ctx, "lyrics-api", "Lyrics API")
	if err != nil {
		t.Fatal(err)
	}
	e, err := deps.Stores.Envs.Create(ctx, p.ID, "prod", "Prod")
	if err != nil {
		t.Fatal(err)
	}

	for _, kv := range [][2]string{
		{"AAA", "first"},
		{"BBB", "second"},
		{"CCC", "third"},
	} {
		ct, err := crypto.Encrypt(id, []byte(kv[1]))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := deps.Stores.Secrets.Upsert(ctx, e.ID, kv[0], ct, 0); err != nil {
			t.Fatal(err)
		}
	}

	plain, _, err := deps.Stores.Tokens.Mint(ctx, p.ID, e.ID, "test", nil)
	if err != nil {
		t.Fatal(err)
	}

	return &harness{
		server: srv, deps: deps, identity: id,
		project: p, env: e, token: plain,
	}
}

func get(t *testing.T, url string, headers map[string]string) (int, string) {
	t.Helper()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func TestRenderRejectsMissingToken(t *testing.T) {
	t.Parallel()

	h := newRenderHarness(t)
	status, _ := get(t, h.server.URL+"/render", nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", status)
	}
}

func TestRenderRejectsBadToken(t *testing.T) {
	t.Parallel()

	h := newRenderHarness(t)
	status, body := get(t, h.server.URL+"/render", map[string]string{
		"Authorization": "Bearer not-a-real-token",
	})
	if status != http.StatusUnauthorized || !strings.Contains(body, "unknown") {
		t.Fatalf("status=%d body=%q", status, body)
	}
}

func TestRenderRejectsRevokedToken(t *testing.T) {
	t.Parallel()

	h := newRenderHarness(t)

	tok, err := h.deps.Stores.Tokens.Lookup(context.Background(), h.token)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.deps.Stores.Tokens.Revoke(context.Background(), tok.ID); err != nil {
		t.Fatal(err)
	}

	status, body := get(t, h.server.URL+"/render", map[string]string{
		"Authorization": "Bearer " + h.token,
	})
	if status != http.StatusUnauthorized || !strings.Contains(body, "revoked") {
		t.Fatalf("status=%d body=%q", status, body)
	}
}

func TestRenderRejectsExpiredToken(t *testing.T) {
	t.Parallel()

	h := newRenderHarness(t)

	exp := h.deps.Now().Add(-1 * time.Hour).Unix()
	plain, _, err := h.deps.Stores.Tokens.Mint(context.Background(), h.project.ID, h.env.ID, "expired", &exp)
	if err != nil {
		t.Fatal(err)
	}

	status, body := get(t, h.server.URL+"/render", map[string]string{
		"Authorization": "Bearer " + plain,
	})
	if status != http.StatusUnauthorized || !strings.Contains(body, "expired") {
		t.Fatalf("status=%d body=%q", status, body)
	}
}

func TestRenderReturns503WhenSealed(t *testing.T) {
	t.Parallel()

	h := newRenderHarness(t)
	h.deps.Vault.Lock()

	status, body := get(t, h.server.URL+"/render", map[string]string{
		"Authorization": "Bearer " + h.token,
	})
	if status != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", status)
	}
	if !strings.Contains(body, "sealed") {
		t.Fatalf("body = %q, expected 'sealed'", body)
	}
}

func TestRenderReturnsSortedKeyValueLines(t *testing.T) {
	t.Parallel()

	h := newRenderHarness(t)

	status, body := get(t, h.server.URL+"/render", map[string]string{
		"Authorization": "Bearer " + h.token,
	})
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	want := "AAA=first\nBBB=second\nCCC=third\n"
	if body != want {
		t.Fatalf("body = %q, want %q", body, want)
	}
}

func TestRenderEmptyEnvReturns200EmptyBody(t *testing.T) {
	t.Parallel()

	h := newRenderHarness(t)

	ctx := context.Background()
	empty, err := h.deps.Stores.Envs.Create(ctx, h.project.ID, "empty", "Empty")
	if err != nil {
		t.Fatal(err)
	}
	plain, _, err := h.deps.Stores.Tokens.Mint(ctx, h.project.ID, empty.ID, "empty", nil)
	if err != nil {
		t.Fatal(err)
	}

	status, body := get(t, h.server.URL+"/render", map[string]string{
		"Authorization": "Bearer " + plain,
	})
	if status != http.StatusOK || body != "" {
		t.Fatalf("status=%d body=%q", status, body)
	}
}

func TestRenderTouchesLastUsedAndAuditsOnSuccess(t *testing.T) {
	t.Parallel()

	h := newRenderHarness(t)

	if status, _ := get(t, h.server.URL+"/render", map[string]string{
		"Authorization": "Bearer " + h.token,
	}); status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}

	tok, err := h.deps.Stores.Tokens.Lookup(context.Background(), h.token)
	if err != nil {
		t.Fatal(err)
	}
	if !tok.LastUsedAt.Valid {
		t.Fatal("last_used_at not set after /render")
	}

	entries, err := h.deps.Stores.Audit.List(context.Background(), 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.Action == "render" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("no render audit entry; got %+v", entries)
	}
}
