package auth

import (
	"context"
	"net/http"
	"time"
)

// SessionCookie is the cookie name keep uses to carry signed sessions.
const SessionCookie = "keep_session"

type ctxKey int

const sessionCtxKey ctxKey = 1

// SessionFromContext retrieves the Session attached by RequireSession.
func SessionFromContext(ctx context.Context) (Session, bool) {
	s, ok := ctx.Value(sessionCtxKey).(Session)
	return s, ok
}

// WithSession attaches s to ctx so downstream handlers can call
// SessionFromContext.
func WithSession(ctx context.Context, s Session) context.Context {
	return context.WithValue(ctx, sessionCtxKey, s)
}

// RequireSession decodes the session cookie and either passes through (with
// the session attached to context) or 303-redirects to /login.
func RequireSession(key []byte, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(SessionCookie)
		if err != nil {
			redirectLogin(w, r)
			return
		}
		s, err := DecodeSession(c.Value, key, time.Now().Unix())
		if err != nil {
			redirectLogin(w, r)
			return
		}
		ctx := context.WithValue(r.Context(), sessionCtxKey, s)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func redirectLogin(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// SetSessionCookie writes the signed session into a secure cookie.
func SetSessionCookie(w http.ResponseWriter, s Session, key []byte, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    EncodeSession(s, key),
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   SessionMaxAge,
	})
}

// ClearSessionCookie expires the session cookie at the client.
func ClearSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}
