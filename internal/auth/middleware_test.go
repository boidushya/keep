package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRequireSessionRedirectsWithoutCookie(t *testing.T) {
	t.Parallel()

	mw := RequireSession(testKey, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler should not run")
	}))

	req := httptest.NewRequest("GET", "/dashboard", nil)
	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther && rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want redirect", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "/login" {
		t.Fatalf("location = %q, want /login", loc)
	}
}

func TestRequireSessionPassesWithValidCookie(t *testing.T) {
	t.Parallel()

	called := false
	mw := RequireSession(testKey, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		s, ok := SessionFromContext(r.Context())
		if !ok {
			t.Fatal("session missing from context")
		}
		if s.UserID != 1 {
			t.Errorf("user id = %d", s.UserID)
		}
	}))

	tok := EncodeSession(Session{UserID: 1, IssuedAt: time.Now().Unix()}, testKey)
	req := httptest.NewRequest("GET", "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookie, Value: tok})
	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	if !called {
		t.Fatal("inner handler not called")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
}

func TestRequireSessionRedirectsOnExpired(t *testing.T) {
	t.Parallel()

	mw := RequireSession(testKey, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler should not run")
	}))

	tok := EncodeSession(
		Session{UserID: 1, IssuedAt: time.Now().Add(-31 * 24 * time.Hour).Unix()},
		testKey,
	)
	req := httptest.NewRequest("GET", "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookie, Value: tok})
	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	if rr.Header().Get("Location") != "/login" {
		t.Fatalf("expected /login redirect, got %q", rr.Header().Get("Location"))
	}
}
