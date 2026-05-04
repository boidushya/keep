package server

import (
	"net/http"

	"github.com/boidushya/keep/internal/auth"
)

// requireAuth gates a handler behind a valid session AND an unsealed vault.
// The key used to verify the cookie comes from Vault.SessionKey(), so a
// restart (which clears the in-memory key) automatically invalidates every
// outstanding session.
func requireAuth(deps Deps) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := deps.Vault.SessionKey()
			if key == nil {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			c, err := r.Cookie(auth.SessionCookie)
			if err != nil {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			s, err := auth.DecodeSession(c.Value, key, deps.now())
			if err != nil {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			ctx := r.Context()
			ctx = auth.WithSession(ctx, s)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// requireTOTPVerified blocks access until the user has confirmed their TOTP
// setup by entering a valid code (recovery codes do not satisfy this gate).
// Mount AFTER requireAuth.
func requireTOTPVerified(deps Deps) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, err := deps.Stores.Users.Get(r.Context())
			if err != nil {
				http.Redirect(w, r, "/setup", http.StatusSeeOther)
				return
			}
			if !user.TOTPVerified {
				http.Redirect(w, r, "/setup/verify", http.StatusSeeOther)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
