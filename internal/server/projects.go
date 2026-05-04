package server

import (
	"context"
	"errors"
	"log"
	"net/http"
	"regexp"

	"github.com/boidushya/keep/internal/store"
	"github.com/go-chi/chi/v5"
)

var slugRE = regexp.MustCompile(`^[a-z0-9-]+$`)
var keyRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type projectListRow struct {
	store.Project
	EnvCount    int
	SecretCount int
}

func dashboardHandler(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		projects, err := deps.Stores.Projects.List(ctx)
		if err != nil {
			httpError(w, http.StatusInternalServerError, "list projects")
			return
		}

		rows := make([]projectListRow, 0, len(projects))
		for _, p := range projects {
			row := projectListRow{Project: p}
			row.EnvCount, row.SecretCount = countProjectChildren(ctx, deps, p.ID)
			rows = append(rows, row)
		}

		renderHTML(w, deps, "dashboard", map[string]any{
			"Title":    "Projects",
			"Session":  sessionFor(r),
			"Projects": rows,
		})
	}
}

func countProjectChildren(ctx context.Context, deps Deps, projectID int) (int, int) {
	envs, err := deps.Stores.Envs.ListByProject(ctx, projectID)
	if err != nil {
		return 0, 0
	}
	secrets := 0
	for _, e := range envs {
		ss, err := deps.Stores.Secrets.ListByEnv(ctx, e.ID)
		if err == nil {
			secrets += len(ss)
		}
	}
	return len(envs), secrets
}

func projectNewGetHandler(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		renderHTML(w, deps, "project_new", map[string]any{
			"Title":   "New project",
			"Session": sessionFor(r),
			"Slug":    "",
			"Name":    "",
			"Error":   "",
		})
	}
}

func projectCreateHandler(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			httpError(w, http.StatusBadRequest, "bad form")
			return
		}
		slug := r.FormValue("slug")
		name := r.FormValue("name")

		if !slugRE.MatchString(slug) {
			renderHTML(w, deps, "project_new", map[string]any{
				"Title":   "New project",
				"Session": sessionFor(r),
				"Slug":    slug,
				"Name":    name,
				"Error":   "Slug must be lowercase letters, digits, and hyphens.",
			})
			return
		}
		if name == "" {
			renderHTML(w, deps, "project_new", map[string]any{
				"Title":   "New project",
				"Session": sessionFor(r),
				"Slug":    slug,
				"Name":    name,
				"Error":   "Name is required.",
			})
			return
		}

		if _, err := deps.Stores.Projects.Create(r.Context(), slug, name); err != nil {
			renderHTML(w, deps, "project_new", map[string]any{
				"Title":   "New project",
				"Session": sessionFor(r),
				"Slug":    slug,
				"Name":    name,
				"Error":   "Slug must be unique.",
			})
			return
		}
		http.Redirect(w, r, "/projects/"+slug, http.StatusSeeOther)
	}
}

func envDeleteHandler(deps Deps) http.HandlerFunc {
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
		if r.FormValue("confirm") != env.Slug {
			http.Redirect(w, r, "/projects/"+project.Slug+"?env="+env.Slug+"&error=confirm", http.StatusSeeOther)
			return
		}
		if err := deps.Stores.Envs.Delete(r.Context(), env.ID); err != nil {
			httpError(w, http.StatusInternalServerError, "delete")
			return
		}
		_ = deps.Stores.Audit.Append(r.Context(), store.AuditEntry{
			At:     deps.now(),
			Actor:  "user:1",
			Action: "env.delete",
			Target: "envs/" + env.Slug,
		})
		http.Redirect(w, r, "/projects/"+project.Slug, http.StatusSeeOther)
	}
}

func envCreateHandler(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slug := chi.URLParam(r, "slug")
		if err := r.ParseForm(); err != nil {
			httpError(w, http.StatusBadRequest, "bad form")
			return
		}
		envSlug := r.FormValue("slug")
		envName := r.FormValue("name")

		ctx := r.Context()
		project, err := deps.Stores.Projects.GetBySlug(ctx, slug)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if !slugRE.MatchString(envSlug) || envName == "" {
			http.Redirect(w, r, "/projects/"+slug+"?error=bad_env", http.StatusSeeOther)
			return
		}

		if _, err := deps.Stores.Envs.Create(ctx, project.ID, envSlug, envName); err != nil {
			log.Printf("env create: %v", err)
			http.Redirect(w, r, "/projects/"+slug+"?error=env_exists", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/projects/"+slug+"?env="+envSlug, http.StatusSeeOther)
	}
}

func sessionFor(r *http.Request) any {
	// We don't need anything from the session in the templates besides "is
	// logged in?", so pass a non-nil placeholder for {{if .Session}}.
	if _, err := r.Cookie("keep_session"); err == nil {
		return map[string]any{"UserID": 1}
	}
	return nil
}

// quiet errors-package import since some helpers may not need it once the
// flow is finalized.
var _ = errors.Is
