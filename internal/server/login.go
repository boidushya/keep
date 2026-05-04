package server

import (
	"context"
	"log"
	"net/http"
	"runtime/debug"

	"filippo.io/age"

	"github.com/boidushya/keep/internal/auth"
	"github.com/boidushya/keep/internal/crypto"
	"github.com/boidushya/keep/internal/store"
)

func loginGetHandler(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		exists, err := userExists(r.Context(), deps)
		if err != nil {
			httpError(w, http.StatusInternalServerError, "internal error")
			return
		}
		if !exists {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}
		renderHTML(w, deps, "login", map[string]any{
			"Title":   "Sign in",
			"Session": nil,
			"Error":   "",
		})
	}
}

func loginPostHandler(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			httpError(w, http.StatusBadRequest, "bad form")
			return
		}

		password := r.FormValue("password")
		code := r.FormValue("totp")

		ctx := r.Context()
		user, err := deps.Stores.Users.Get(ctx)
		if err != nil {
			renderLoginError(w, deps, "Wrong password or code.")
			return
		}

		ok, err := auth.VerifyPassword(user.PasswordHash, password)
		if err != nil || !ok {
			auditLogin(ctx, deps, "login.fail.password")
			renderLoginError(w, deps, "Wrong password or code.")
			return
		}

		identity, err := unwrapMasterIdentity(ctx, deps, password)
		if err != nil {
			auditLogin(ctx, deps, "login.fail.unwrap")
			renderLoginError(w, deps, "Wrong password or code.")
			return
		}

		secretBytes, err := crypto.Decrypt(identity, user.TotpSecretEncrypted)
		if err != nil {
			auditLogin(ctx, deps, "login.fail.totp_decrypt")
			renderLoginError(w, deps, "Wrong password or code.")
			return
		}
		if !auth.VerifyTOTP(string(secretBytes), code) {
			auditLogin(ctx, deps, "login.fail.totp")
			renderLoginError(w, deps, "Wrong password or code.")
			return
		}

		finishLogin(w, r, deps, identity)
	}
}

func loginRecoveryGetHandler(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		renderHTML(w, deps, "login_recovery", map[string]any{
			"Title":   "Recovery sign in",
			"Session": nil,
			"Error":   "",
		})
	}
}

func loginRecoveryPostHandler(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			httpError(w, http.StatusBadRequest, "bad form")
			return
		}

		password := r.FormValue("password")
		code := r.FormValue("recovery_code")

		ctx := r.Context()
		user, err := deps.Stores.Users.Get(ctx)
		if err != nil {
			renderRecoveryError(w, deps, "Wrong password or code.")
			return
		}

		ok, err := auth.VerifyPassword(user.PasswordHash, password)
		if err != nil || !ok {
			renderRecoveryError(w, deps, "Wrong password or code.")
			return
		}

		identity, err := unwrapMasterIdentity(ctx, deps, password)
		if err != nil {
			renderRecoveryError(w, deps, "Wrong password or code.")
			return
		}

		codesJSON, err := crypto.Decrypt(identity, user.RecoveryCodesEncrypted)
		if err != nil {
			renderRecoveryError(w, deps, "Wrong password or code.")
			return
		}
		codes, err := auth.UnmarshalRecoveryCodes(codesJSON)
		if err != nil {
			renderRecoveryError(w, deps, "Wrong password or code.")
			return
		}

		left, consumed := auth.ConsumeRecoveryCode(codes, code)
		if !consumed {
			auditLogin(ctx, deps, "login.fail.recovery")
			renderRecoveryError(w, deps, "Wrong password or code.")
			return
		}
		newJSON, err := auth.MarshalRecoveryCodes(left)
		if err != nil {
			httpError(w, http.StatusInternalServerError, "internal error")
			return
		}
		newEnc, err := crypto.Encrypt(identity, newJSON)
		if err != nil {
			httpError(w, http.StatusInternalServerError, "internal error")
			return
		}
		if err := deps.Stores.Users.UpdateRecoveryCodes(ctx, newEnc); err != nil {
			httpError(w, http.StatusInternalServerError, "internal error")
			return
		}

		finishLogin(w, r, deps, identity)
	}
}

func logoutHandler(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth.ClearSessionCookie(w, deps.SecureCookies)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

func adminSealHandler(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		deps.Vault.Lock()
		auth.ClearSessionCookie(w, deps.SecureCookies)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

func unwrapMasterIdentity(ctx context.Context, deps Deps, password string) (*age.X25519Identity, error) {
	salt, wrapped, err := loadMasterEnvelope(ctx, deps)
	if err != nil {
		return nil, err
	}
	return crypto.UnwrapIdentity(wrapped, salt, password)
}

func finishLogin(w http.ResponseWriter, r *http.Request, deps Deps, identity *age.X25519Identity) {
	if err := deps.Vault.Unlock(identity); err != nil {
		log.Printf("login: unlock: %v", err)
		httpError(w, http.StatusInternalServerError, "unlock failed")
		return
	}
	auth.SetSessionCookie(w, auth.Session{
		UserID:   1,
		IssuedAt: deps.now(),
	}, deps.Vault.SessionKey(), deps.SecureCookies)
	_ = deps.Stores.Users.UpdateLastLogin(r.Context(), deps.now())
	auditLogin(r.Context(), deps, "login.success")
	http.Redirect(w, r, "/", http.StatusSeeOther)

	// Argon2id allocates ~256 MiB during the KDF that just ran. Without this
	// nudge, Go keeps it in the heap and RSS stays high until the next GC
	// cycle organically releases it. The stop-the-world pause is small
	// (<100ms) and runs after the redirect is already in flight.
	debug.FreeOSMemory()
}

func renderLoginError(w http.ResponseWriter, deps Deps, msg string) {
	w.WriteHeader(http.StatusUnauthorized)
	renderHTML(w, deps, "login", map[string]any{
		"Title":   "Sign in",
		"Session": nil,
		"Error":   msg,
	})
}

func renderRecoveryError(w http.ResponseWriter, deps Deps, msg string) {
	w.WriteHeader(http.StatusUnauthorized)
	renderHTML(w, deps, "login_recovery", map[string]any{
		"Title":   "Recovery sign in",
		"Session": nil,
		"Error":   msg,
	})
}

func auditLogin(ctx context.Context, deps Deps, action string) {
	_ = deps.Stores.Audit.Append(ctx, store.AuditEntry{
		At:     deps.now(),
		Actor:  "user:1",
		Action: action,
		Target: "users/1",
	})
}
