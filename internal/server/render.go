package server

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"filippo.io/age"

	"github.com/boidushya/keep/internal/crypto"
	"github.com/boidushya/keep/internal/store"
)

func renderHandler(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r)
		if !ok {
			writePlain(w, http.StatusUnauthorized, "missing bearer token")
			return
		}

		ctx := r.Context()
		tok, err := deps.Stores.Tokens.Lookup(ctx, token)
		switch {
		case errors.Is(err, store.ErrNotFound):
			writePlain(w, http.StatusUnauthorized, "unknown token")
			return
		case errors.Is(err, store.ErrTokenRevoked):
			writePlain(w, http.StatusUnauthorized, "token revoked")
			return
		case errors.Is(err, store.ErrTokenExpired):
			writePlain(w, http.StatusUnauthorized, "token expired")
			return
		case err != nil:
			writePlain(w, http.StatusInternalServerError, "lookup failed")
			return
		}

		if deps.Vault.IsSealed() {
			writePlain(w, http.StatusServiceUnavailable,
				"keep is sealed: operator must log in to unlock")
			return
		}
		identity := deps.Vault.Identity()

		secrets, err := deps.Stores.Secrets.ListByEnv(ctx, tok.EnvID)
		if err != nil {
			writePlain(w, http.StatusInternalServerError, "load secrets failed")
			return
		}

		body, err := renderEnvFile(identity, secrets)
		if err != nil {
			writePlain(w, http.StatusInternalServerError, fmt.Sprintf("render: %s", err))
			return
		}

		_ = deps.Stores.Tokens.TouchLastUsed(ctx, tok.ID, deps.now())
		_ = deps.Stores.Audit.Append(ctx, store.AuditEntry{
			At:       deps.now(),
			Actor:    fmt.Sprintf("token:%d", tok.ID),
			Action:   "render",
			Target:   fmt.Sprintf("envs/%d", tok.EnvID),
			Metadata: fmt.Sprintf(`{"keys":%d}`, len(secrets)),
		})

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}
}

// renderEnvFile decrypts every secret and emits KEY=VALUE\n lines. Secrets are
// already sorted by key (Secrets.ListByEnv ORDERs by key). Multiline values
// are rejected because the agent script does not handle escaping.
func renderEnvFile(identity *age.X25519Identity, secrets []store.Secret) ([]byte, error) {
	var b strings.Builder
	for _, s := range secrets {
		val, err := crypto.Decrypt(identity, s.ValueEncrypted)
		if err != nil {
			return nil, fmt.Errorf("decrypt %q: %w", s.Key, err)
		}
		if strings.ContainsAny(string(val), "\n\r") {
			return nil, fmt.Errorf("secret %q contains a newline; multiline values are not supported", s.Key)
		}
		b.WriteString(s.Key)
		b.WriteByte('=')
		b.Write(val)
		b.WriteByte('\n')
	}
	return []byte(b.String()), nil
}

// bearerToken returns the token from "Authorization: Bearer <token>" or false.
func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	tok := strings.TrimSpace(h[len(prefix):])
	if tok == "" {
		return "", false
	}
	return tok, true
}

func writePlain(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}
