package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	keepdb "github.com/boidushya/keep/internal/db"
	"github.com/boidushya/keep/internal/ui"
)

func newServerWithUI(t *testing.T) *httptest.Server {
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

	deps := Deps{
		DB:        d,
		Vault:     NewVault(),
		Now:       func() time.Time { return time.Unix(1000, 0) },
		Stores:    NewStores(d, func() time.Time { return time.Unix(1000, 0) }),
		Templates: tt,
	}

	srv := httptest.NewServer(New(deps))
	t.Cleanup(srv.Close)
	return srv
}

func TestStaticServesEmbeddedCSS(t *testing.T) {
	t.Parallel()

	srv := newServerWithUI(t)
	resp, err := http.Get(srv.URL + "/static/keep.css")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "tailwindcss") && !strings.Contains(string(body), "color-scheme") {
		head := body
		if len(head) > 120 {
			head = head[:120]
		}
		t.Fatalf("css content unexpected: %q", string(head))
	}
}

func TestRootRedirectsToLoginWhenSealed(t *testing.T) {
	t.Parallel()

	srv := newServerWithUI(t)
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/login" {
		t.Fatalf("location = %q", loc)
	}
}

