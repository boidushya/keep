package server

import (
	"context"
	"log"
	"net/http"
	"strconv"

	"github.com/boidushya/keep/internal/auth"
	"github.com/boidushya/keep/internal/crypto"
	"github.com/boidushya/keep/internal/store"
	"github.com/go-chi/chi/v5"
)

type secretRow struct {
	store.Secret
	PlainValue string
	UpdatedRel string
}

type versionRow struct {
	Version int
	WhenRel string
	Plain   string
}

func projectPageHandler(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		slug := chi.URLParam(r, "slug")
		project, err := deps.Stores.Projects.GetBySlug(ctx, slug)
		if err != nil {
			http.NotFound(w, r)
			return
		}

		envs, err := deps.Stores.Envs.ListByProject(ctx, project.ID)
		if err != nil {
			httpError(w, http.StatusInternalServerError, "list envs")
			return
		}

		// Pick env: ?env=<slug>, else first.
		envSlug := r.URL.Query().Get("env")
		var current store.Env
		if len(envs) > 0 {
			current = envs[0]
			for _, e := range envs {
				if e.Slug == envSlug {
					current = e
					break
				}
			}
		}

		var rows []secretRow
		if current.ID != 0 {
			secs, err := deps.Stores.Secrets.ListByEnv(ctx, current.ID)
			if err != nil {
				httpError(w, http.StatusInternalServerError, "list secrets")
				return
			}
			id := deps.Vault.Identity()
			rows = make([]secretRow, 0, len(secs))
			for _, s := range secs {
				plain, err := crypto.Decrypt(id, s.ValueEncrypted)
				if err != nil {
					log.Printf("decrypt %s/%s/%s: %v", project.Slug, current.Slug, s.Key, err)
					rows = append(rows, secretRow{Secret: s, PlainValue: "(decrypt error)"})
					continue
				}
				rows = append(rows, secretRow{
					Secret:     s,
					PlainValue: string(plain),
					UpdatedRel: relTime(s.UpdatedAt, deps.now()),
				})
			}
		}

		errMsg := ""
		switch r.URL.Query().Get("error") {
		case "bad_env":
			errMsg = "Env slug must be lowercase letters/digits/hyphens, with a name."
		case "env_exists":
			errMsg = "An env with that slug already exists."
		}

		renderHTML(w, deps, "project", map[string]any{
			"Title":   project.Slug,
			"Session": sessionFor(r),
			"Project": project,
			"Envs":    envs,
			"Env":     current,
			"Secrets": rows,
			"Error":   errMsg,
		})
	}
}

func secretCreateHandler(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			httpError(w, http.StatusBadRequest, "bad form")
			return
		}
		project, env, ok := loadProjectEnv(deps, r)
		if !ok {
			http.NotFound(w, r)
			return
		}
		key := r.FormValue("key")
		value := r.FormValue("value")
		if !keyRE.MatchString(key) || value == "" {
			http.Redirect(w, r, "/projects/"+project.Slug+"?env="+env.Slug, http.StatusSeeOther)
			return
		}

		identity := deps.Vault.Identity()
		ct, err := crypto.Encrypt(identity, []byte(value))
		if err != nil {
			httpError(w, http.StatusInternalServerError, "encrypt")
			return
		}
		_, err = deps.Stores.Secrets.Upsert(r.Context(), env.ID, key, ct, userIDFor(r))
		if err != nil {
			log.Printf("upsert: %v", err)
			httpError(w, http.StatusInternalServerError, "save")
			return
		}
		appendSecretAudit(r.Context(), deps, "secret.create", env.ID, key)
		http.Redirect(w, r, "/projects/"+project.Slug+"?env="+env.Slug, http.StatusSeeOther)
	}
}

func secretEditHandler(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		project, env, ok := loadProjectEnv(deps, r)
		if !ok {
			http.NotFound(w, r)
			return
		}
		key := chi.URLParam(r, "key")
		s, err := deps.Stores.Secrets.GetByKey(r.Context(), env.ID, key)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		plain, err := crypto.Decrypt(deps.Vault.Identity(), s.ValueEncrypted)
		if err != nil {
			httpError(w, http.StatusInternalServerError, "decrypt")
			return
		}
		renderHTML(w, deps, "secret_edit", map[string]any{
			"Title":          "Edit " + key,
			"Session":        sessionFor(r),
			"Project":        project,
			"Env":            env,
			"Key":            key,
			"PlainValue":     string(plain),
			"CurrentVersion": s.CurrentVersion,
		})
	}
}

func secretBulkImportHandler(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			httpError(w, http.StatusBadRequest, "bad form")
			return
		}
		project, env, ok := loadProjectEnv(deps, r)
		if !ok {
			http.NotFound(w, r)
			return
		}
		entries, err := parseDotenv(r.FormValue("env"))
		if err != nil {
			http.Redirect(w, r, "/projects/"+project.Slug+"?env="+env.Slug+"&error=bulk", http.StatusSeeOther)
			return
		}
		identity := deps.Vault.Identity()
		ctx := r.Context()
		uid := userIDFor(r)
		for _, e := range entries {
			ct, err := crypto.Encrypt(identity, []byte(e.value))
			if err != nil {
				httpError(w, http.StatusInternalServerError, "encrypt")
				return
			}
			if _, err := deps.Stores.Secrets.Upsert(ctx, env.ID, e.key, ct, uid); err != nil {
				log.Printf("bulk upsert %s: %v", e.key, err)
				httpError(w, http.StatusInternalServerError, "save")
				return
			}
			appendSecretAudit(ctx, deps, "secret.import", env.ID, e.key)
		}
		http.Redirect(w, r, "/projects/"+project.Slug+"?env="+env.Slug, http.StatusSeeOther)
	}
}

func secretMutateHandler(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			httpError(w, http.StatusBadRequest, "bad form")
			return
		}
		project, env, ok := loadProjectEnv(deps, r)
		if !ok {
			http.NotFound(w, r)
			return
		}
		key := chi.URLParam(r, "key")
		op := r.FormValue("op")

		ctx := r.Context()
		switch op {
		case "delete":
			s, err := deps.Stores.Secrets.GetByKey(ctx, env.ID, key)
			if err != nil {
				http.NotFound(w, r)
				return
			}
			if err := deps.Stores.Secrets.Delete(ctx, s.ID); err != nil {
				httpError(w, http.StatusInternalServerError, "delete")
				return
			}
			appendSecretAudit(ctx, deps, "secret.delete", env.ID, key)
		default: // update
			value := r.FormValue("value")
			if value == "" {
				http.Redirect(w, r, "/projects/"+project.Slug+"?env="+env.Slug, http.StatusSeeOther)
				return
			}
			ct, err := crypto.Encrypt(deps.Vault.Identity(), []byte(value))
			if err != nil {
				httpError(w, http.StatusInternalServerError, "encrypt")
				return
			}
			_, err = deps.Stores.Secrets.Upsert(ctx, env.ID, key, ct, userIDFor(r))
			if err != nil {
				log.Printf("upsert: %v", err)
				httpError(w, http.StatusInternalServerError, "save")
				return
			}
			appendSecretAudit(ctx, deps, "secret.update", env.ID, key)
		}
		http.Redirect(w, r, "/projects/"+project.Slug+"?env="+env.Slug, http.StatusSeeOther)
	}
}

func secretVersionsHandler(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		project, env, ok := loadProjectEnv(deps, r)
		if !ok {
			http.NotFound(w, r)
			return
		}
		key := chi.URLParam(r, "key")
		ctx := r.Context()
		s, err := deps.Stores.Secrets.GetByKey(ctx, env.ID, key)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		versions, err := deps.Stores.Secrets.ListVersions(ctx, s.ID)
		if err != nil {
			httpError(w, http.StatusInternalServerError, "list versions")
			return
		}
		identity := deps.Vault.Identity()
		rows := make([]versionRow, 0, len(versions))
		for _, v := range versions {
			plain, err := crypto.Decrypt(identity, v.ValueEncrypted)
			val := string(plain)
			if err != nil {
				val = "(decrypt error)"
			}
			rows = append(rows, versionRow{
				Version: v.Version,
				WhenRel: relTime(v.CreatedAt, deps.now()),
				Plain:   val,
			})
		}
		renderHTML(w, deps, "secret_versions", map[string]any{
			"Title":    key + " · history",
			"Session":  sessionFor(r),
			"Project":  project,
			"Env":      env,
			"Key":      key,
			"Versions": rows,
		})
	}
}

func secretRestoreHandler(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		project, env, ok := loadProjectEnv(deps, r)
		if !ok {
			http.NotFound(w, r)
			return
		}
		key := chi.URLParam(r, "key")
		version, err := strconv.Atoi(chi.URLParam(r, "version"))
		if err != nil || version <= 0 {
			http.NotFound(w, r)
			return
		}

		ctx := r.Context()
		s, err := deps.Stores.Secrets.GetByKey(ctx, env.ID, key)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if _, err := deps.Stores.Secrets.RestoreVersion(ctx, s.ID, version, userIDFor(r)); err != nil {
			httpError(w, http.StatusInternalServerError, "restore")
			return
		}
		appendSecretAudit(ctx, deps, "secret.restore", env.ID, key)
		http.Redirect(w, r, "/projects/"+project.Slug+"?env="+env.Slug, http.StatusSeeOther)
	}
}

func loadProjectEnv(deps Deps, r *http.Request) (store.Project, store.Env, bool) {
	ctx := r.Context()
	pSlug := chi.URLParam(r, "slug")
	eSlug := chi.URLParam(r, "env")

	project, err := deps.Stores.Projects.GetBySlug(ctx, pSlug)
	if err != nil {
		return store.Project{}, store.Env{}, false
	}
	env, err := deps.Stores.Envs.GetBySlug(ctx, project.ID, eSlug)
	if err != nil {
		return project, store.Env{}, false
	}
	return project, env, true
}

func userIDFor(r *http.Request) int {
	if s, ok := auth.SessionFromContext(r.Context()); ok {
		return s.UserID
	}
	return 0
}

func appendSecretAudit(ctx context.Context, deps Deps, action string, envID int, key string) {
	_ = deps.Stores.Audit.Append(ctx, store.AuditEntry{
		At:     deps.now(),
		Actor:  "user:1",
		Action: action,
		Target: "envs/" + strconv.Itoa(envID) + "/secrets/" + key,
	})
}
