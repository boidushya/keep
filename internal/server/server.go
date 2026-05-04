// Package server exposes the HTTP layer: a chi router, the sealed-state Vault,
// and per-resource handlers. It depends on the store and crypto packages but
// nothing in cmd/.
package server

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/boidushya/keep/internal/store"
	"github.com/boidushya/keep/internal/ui"
	"github.com/boidushya/keep/web"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// Deps is the server's dependency bag. All callers (cmd/keep, tests) build it.
type Deps struct {
	DB    *sql.DB
	Vault *Vault
	Now   func() time.Time

	// PublicURL is the externally-visible base URL (e.g.
	// "https://keep.boidu.dev"). Used to build the Endpoint embedded in
	// generated agent scripts.
	PublicURL string

	// SecureCookies sets the Secure flag on session cookies. Must be true
	// when serving over HTTPS in production; false for plaintext local
	// development.
	SecureCookies bool

	// Stores is the typed access object set. Construct with NewStores.
	Stores Stores

	// Templates renders HTML pages. Construct with ui.New.
	Templates *ui.Templates
}

// Stores groups the store types so handlers can read what they need.
type Stores struct {
	Users    store.Users
	Projects store.Projects
	Envs     store.Envs
	Secrets  store.Secrets
	Tokens   store.Tokens
	Audit    store.Audit
}

// NewStores returns a Stores set bound to db with a shared Now function.
func NewStores(db *sql.DB, now func() time.Time) Stores {
	return Stores{
		Users:    store.Users{DB: db, Now: now},
		Projects: store.Projects{DB: db, Now: now},
		Envs:     store.Envs{DB: db, Now: now},
		Secrets:  store.Secrets{DB: db, Now: now},
		Tokens:   store.Tokens{DB: db, Now: now},
		Audit:    store.Audit{DB: db},
	}
}

// New builds the chi router with all routes mounted.
func New(deps Deps) *chi.Mux {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	r.Get("/render", renderHandler(deps))

	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.FS(web.Dist()))))

	// Setup + login + recovery + logout + seal.
	r.Get("/setup", setupGetHandler(deps))
	r.Post("/setup", setupPostHandler(deps))
	r.Get("/login", loginGetHandler(deps))
	r.Post("/login", loginPostHandler(deps))
	r.Get("/login/recovery", loginRecoveryGetHandler(deps))
	r.Post("/login/recovery", loginRecoveryPostHandler(deps))
	r.Post("/logout", logoutHandler(deps))
	r.Post("/admin/seal", adminSealHandler(deps))

	// /setup/verify is auth-gated (must have a session) but NOT
	// totp-verified-gated (it IS the gate).
	r.Group(func(r chi.Router) {
		r.Use(requireAuth(deps))
		r.Get("/setup/verify", setupVerifyGetHandler(deps))
		r.Post("/setup/verify", setupVerifyPostHandler(deps))
	})

	// Authenticated app pages. Locked behind both a valid session and a
	// confirmed TOTP setup.
	r.Group(func(r chi.Router) {
		r.Use(requireAuth(deps))
		r.Use(requireTOTPVerified(deps))

		r.Get("/", dashboardHandler(deps))
		r.Get("/projects/new", projectNewGetHandler(deps))
		r.Post("/projects", projectCreateHandler(deps))

		r.Get("/projects/{slug}", projectPageHandler(deps))
		r.Post("/projects/{slug}/envs", envCreateHandler(deps))
		r.Post("/projects/{slug}/envs/{env}/delete", envDeleteHandler(deps))

		r.Post("/projects/{slug}/envs/{env}/secrets", secretCreateHandler(deps))
		r.Post("/projects/{slug}/envs/{env}/secrets/bulk", secretBulkImportHandler(deps))
		r.Get("/projects/{slug}/envs/{env}/secrets/{key}/edit", secretEditHandler(deps))
		r.Post("/projects/{slug}/envs/{env}/secrets/{key}", secretMutateHandler(deps))
		r.Get("/projects/{slug}/envs/{env}/secrets/{key}/versions", secretVersionsHandler(deps))
		r.Post("/projects/{slug}/envs/{env}/secrets/{key}/versions/{version}/restore", secretRestoreHandler(deps))

		r.Get("/projects/{slug}/envs/{env}/tokens", tokensListHandler(deps))
		r.Post("/projects/{slug}/envs/{env}/tokens", tokenMintHandler(deps))
		r.Get("/projects/{slug}/envs/{env}/tokens/{id}/script.sh", tokenScriptHandler(deps))
		r.Post("/projects/{slug}/envs/{env}/tokens/{id}/revoke", tokenRevokeHandler(deps))

		r.Get("/audit", auditHandler(deps))
	})

	return r
}


func (d Deps) now() int64 {
	if d.Now != nil {
		return d.Now().Unix()
	}
	return time.Now().Unix()
}
