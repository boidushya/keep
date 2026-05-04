package server

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"runtime/debug"

	"filippo.io/age"

	"github.com/boidushya/keep/internal/auth"
	"github.com/boidushya/keep/internal/crypto"
	"github.com/boidushya/keep/internal/store"
)

const totpIssuer = "keep"
const totpAccount = "admin"
const recoveryCodeCount = 8

func setupGetHandler(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		exists, err := userExists(r.Context(), deps)
		if err != nil {
			httpError(w, http.StatusInternalServerError, "internal error")
			return
		}
		if exists {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		renderHTML(w, deps, "setup", map[string]any{
			"Title":   "Set up",
			"Session": nil,
			"Error":   "",
		})
	}
}

func setupPostHandler(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		exists, err := userExists(ctx, deps)
		if err != nil {
			httpError(w, http.StatusInternalServerError, "internal error")
			return
		}
		if exists {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		if err := r.ParseForm(); err != nil {
			httpError(w, http.StatusBadRequest, "bad form")
			return
		}

		password := r.FormValue("password")
		confirm := r.FormValue("password_confirm")
		if password == "" || password != confirm {
			renderHTML(w, deps, "setup", map[string]any{
				"Title":   "Set up",
				"Session": nil,
				"Error":   "Passwords did not match.",
			})
			return
		}

		out, err := provisionUser(ctx, deps, password)
		if err != nil {
			log.Printf("setup: provision: %v", err)
			httpError(w, http.StatusInternalServerError, "setup failed")
			return
		}

		// User is now created. Unlock vault, set session cookie, render the
		// "save these codes" page.
		if err := deps.Vault.Unlock(out.identity); err != nil {
			log.Printf("setup: unlock: %v", err)
			httpError(w, http.StatusInternalServerError, "unlock failed")
			return
		}
		auth.SetSessionCookie(w, auth.Session{
			UserID:   1,
			IssuedAt: deps.now(),
		}, deps.Vault.SessionKey(), deps.SecureCookies)
		_ = deps.Stores.Users.UpdateLastLogin(ctx, deps.now())
		auditLogin(ctx, deps, "user.create")
		auditLogin(ctx, deps, "login.success")

		// Render with the recovery codes embedded ONCE. After this response,
		// the codes are never re-shown by the server: GET /setup/verify
		// re-renders the page without them.
		renderHTML(w, deps, "setup_done", map[string]any{
			"Title":         "Confirm authenticator",
			"Session":       map[string]any{"UserID": 1},
			"TOTPSecret":    out.totpSecret,
			"QRBase64":      base64.StdEncoding.EncodeToString(out.qrPNG),
			"RecoveryCodes": out.recoveryCodes,
			"Error":         "",
		})

		// Setup runs three Argon2id calls back-to-back (hash, wrap, derive
		// session key). Return the work buffers to the OS now rather than
		// keeping them in the Go heap.
		debug.FreeOSMemory()
	}
}

// setupVerifyGetHandler shows the TOTP-confirm page on a follow-up visit (no
// recovery codes; those are only shown in the immediate POST /setup response).
func setupVerifyGetHandler(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		user, err := deps.Stores.Users.Get(ctx)
		if err != nil {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}
		if user.TOTPVerified {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		identity := deps.Vault.Identity()
		if identity == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		secret, err := crypto.Decrypt(identity, user.TotpSecretEncrypted)
		if err != nil {
			httpError(w, http.StatusInternalServerError, "decrypt totp")
			return
		}
		qr, err := totpQRForSecret(string(secret))
		if err != nil {
			httpError(w, http.StatusInternalServerError, "totp qr")
			return
		}
		renderHTML(w, deps, "setup_done", map[string]any{
			"Title":         "Confirm authenticator",
			"Session":       map[string]any{"UserID": 1},
			"TOTPSecret":    string(secret),
			"QRBase64":      base64.StdEncoding.EncodeToString(qr),
			"RecoveryCodes": nil,
			"Error":         "",
		})
	}
}

func setupVerifyPostHandler(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			httpError(w, http.StatusBadRequest, "bad form")
			return
		}
		ctx := r.Context()
		user, err := deps.Stores.Users.Get(ctx)
		if err != nil {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}
		if user.TOTPVerified {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		identity := deps.Vault.Identity()
		if identity == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		secret, err := crypto.Decrypt(identity, user.TotpSecretEncrypted)
		if err != nil {
			httpError(w, http.StatusInternalServerError, "decrypt totp")
			return
		}

		code := r.FormValue("totp")
		if !auth.VerifyTOTP(string(secret), code) {
			// Re-render WITHOUT recovery codes. Recovery codes do not
			// satisfy the verify step by design: this gate only proves the
			// user actually configured the authenticator app.
			qr, _ := totpQRForSecret(string(secret))
			renderHTML(w, deps, "setup_done", map[string]any{
				"Title":         "Confirm authenticator",
				"Session":       map[string]any{"UserID": 1},
				"TOTPSecret":    string(secret),
				"QRBase64":      base64.StdEncoding.EncodeToString(qr),
				"RecoveryCodes": nil,
				"Error":         "Code did not match. Try again with the current code from your authenticator.",
			})
			auditLogin(ctx, deps, "setup.verify.fail")
			return
		}

		if err := deps.Stores.Users.MarkTOTPVerified(ctx); err != nil {
			httpError(w, http.StatusInternalServerError, "mark verified")
			return
		}
		auditLogin(ctx, deps, "setup.verify.success")
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

// totpQRForSecret rebuilds the QR PNG for an existing TOTP secret. Used when
// re-rendering the verify page on a follow-up visit.
func totpQRForSecret(secret string) ([]byte, error) {
	// Re-derive a key URL by calling SetupTOTP would generate a *different*
	// secret. Instead build the otpauth URL directly so the QR encodes the
	// stored secret.
	url := "otpauth://totp/" + totpIssuer + ":" + totpAccount +
		"?secret=" + secret + "&issuer=" + totpIssuer
	return auth.QRCodePNG(url, 256)
}

type provisionedUser struct {
	identity      *age.X25519Identity
	totpSecret    string
	qrPNG         []byte
	recoveryCodes []string
}

func provisionUser(ctx context.Context, deps Deps, password string) (provisionedUser, error) {
	hash, err := auth.HashPassword(password)
	if err != nil {
		return provisionedUser{}, fmt.Errorf("hash password: %w", err)
	}

	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return provisionedUser{}, fmt.Errorf("gen identity: %w", err)
	}

	salt, wrapped, err := crypto.WrapIdentity(identity, password)
	if err != nil {
		return provisionedUser{}, fmt.Errorf("wrap identity: %w", err)
	}

	totpSecret, qrPNG, err := auth.SetupTOTP(totpIssuer, totpAccount)
	if err != nil {
		return provisionedUser{}, fmt.Errorf("totp: %w", err)
	}
	totpEnc, err := crypto.Encrypt(identity, []byte(totpSecret))
	if err != nil {
		return provisionedUser{}, fmt.Errorf("totp encrypt: %w", err)
	}

	codes, err := auth.GenerateRecoveryCodes(recoveryCodeCount)
	if err != nil {
		return provisionedUser{}, fmt.Errorf("recovery codes: %w", err)
	}
	codesJSON, err := auth.MarshalRecoveryCodes(codes)
	if err != nil {
		return provisionedUser{}, fmt.Errorf("recovery marshal: %w", err)
	}
	codesEnc, err := crypto.Encrypt(identity, codesJSON)
	if err != nil {
		return provisionedUser{}, fmt.Errorf("recovery encrypt: %w", err)
	}

	if err := deps.Stores.Users.Create(ctx, hash, totpEnc, codesEnc); err != nil {
		return provisionedUser{}, fmt.Errorf("user create: %w", err)
	}

	if err := storeMasterEnvelope(ctx, deps, salt, wrapped); err != nil {
		return provisionedUser{}, fmt.Errorf("envelope: %w", err)
	}

	return provisionedUser{
		identity:      identity,
		totpSecret:    totpSecret,
		qrPNG:         qrPNG,
		recoveryCodes: codes,
	}, nil
}

func storeMasterEnvelope(ctx context.Context, deps Deps, salt, wrapped []byte) error {
	_, err := deps.DB.ExecContext(ctx, `
		INSERT INTO master_key_envelope (id, salt, wrapped_key, created_at)
		VALUES (1, ?, ?, ?)
	`, salt, wrapped, deps.now())
	return err
}

func loadMasterEnvelope(ctx context.Context, deps Deps) (salt, wrapped []byte, err error) {
	err = deps.DB.QueryRowContext(ctx, `
		SELECT salt, wrapped_key FROM master_key_envelope WHERE id = 1
	`).Scan(&salt, &wrapped)
	return salt, wrapped, err
}

func userExists(ctx context.Context, deps Deps) (bool, error) {
	_, err := deps.Stores.Users.Get(ctx)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, store.ErrNoUser) {
		return false, nil
	}
	return false, err
}

// renderHTML renders a UI template. If templates aren't wired (older tests),
// it falls back to a tiny placeholder body.
func renderHTML(w http.ResponseWriter, deps Deps, page string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if deps.Templates == nil {
		fmt.Fprintf(w, "templates not configured")
		return
	}
	if err := deps.Templates.Render(w, page, data); err != nil {
		log.Printf("render %s: %v", page, err)
	}
}

func httpError(w http.ResponseWriter, status int, body string) {
	http.Error(w, body, status)
}

