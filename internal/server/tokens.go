package server

import (
	"database/sql"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/boidushya/keep/internal/store"
	"github.com/go-chi/chi/v5"
)

// PublicURLKey is the name of the deps field that holds the externally-visible
// base URL (used to build the agent script's ENDPOINT). Stored on Deps via the
// PublicURL field.
type tokenRow struct {
	store.Token
	CreatedRel  string
	LastUsedRel string
	ExpiresRel  string
	Revoked     bool
	Expired     bool
}

// recentTokenWindow is how long we keep the just-minted plaintext available
// for download via /tokens/{id}/script.sh. After this, the token must be
// re-minted to get a script.
const recentTokenWindow = 5 * time.Minute

// inMemoryTokenCache holds plaintexts for freshly-minted tokens so the
// /script.sh endpoint can include them. Cleared automatically after
// recentTokenWindow.
var inMemoryTokenCache = newTokenCache()

func tokensListHandler(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		project, env, ok := loadProjectEnv(deps, r)
		if !ok {
			http.NotFound(w, r)
			return
		}
		ctx := r.Context()
		toks, err := deps.Stores.Tokens.ListByEnv(ctx, env.ID)
		if err != nil {
			httpError(w, http.StatusInternalServerError, "list tokens")
			return
		}
		now := deps.now()
		rows := make([]tokenRow, 0, len(toks))
		for _, t := range toks {
			row := tokenRow{
				Token:      t,
				CreatedRel: relTime(t.CreatedAt, now),
			}
			if t.LastUsedAt.Valid {
				row.LastUsedRel = relTime(t.LastUsedAt.Int64, now)
			}
			if t.ExpiresAt.Valid {
				row.ExpiresRel = relTime(t.ExpiresAt.Int64, now)
				if t.ExpiresAt.Int64 <= now {
					row.Expired = true
				}
			}
			if t.RevokedAt.Valid {
				row.Revoked = true
			}
			rows = append(rows, row)
		}

		// Default required-keys list pulled from existing secrets in this env.
		secs, _ := deps.Stores.Secrets.ListByEnv(ctx, env.ID)
		defaultKeys := make([]string, 0, len(secs))
		for _, s := range secs {
			defaultKeys = append(defaultKeys, s.Key)
		}

		renderHTML(w, deps, "tokens", map[string]any{
			"Title":               "Tokens",
			"Session":             sessionFor(r),
			"Project":             project,
			"Env":                 env,
			"Tokens":              rows,
			"RequiredKeysDefault": strings.Join(defaultKeys, " "),
		})
	}
}

func tokenMintHandler(deps Deps) http.HandlerFunc {
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

		name := strings.TrimSpace(r.FormValue("name"))
		if name == "" {
			http.Redirect(w, r, "/projects/"+project.Slug+"/envs/"+env.Slug+"/tokens?error=name", http.StatusSeeOther)
			return
		}

		var expiresAt *int64
		if d := parseExpiry(r.FormValue("expires_in")); d > 0 {
			t := deps.now() + int64(d.Seconds())
			expiresAt = &t
		}

		ctx := r.Context()
		plain, row, err := deps.Stores.Tokens.Mint(ctx, project.ID, env.ID, name, expiresAt)
		if err != nil {
			httpError(w, http.StatusInternalServerError, "mint")
			return
		}
		_ = deps.Stores.Audit.Append(ctx, store.AuditEntry{
			At:     deps.now(),
			Actor:  "user:1",
			Action: "token.mint",
			Target: "tokens/" + strconv.Itoa(row.ID),
		})

		// Keep the plaintext in memory for the script endpoint.
		inMemoryTokenCache.set(row.ID, plain, time.Now().Add(recentTokenWindow))

		// Render the post-mint page (token + agent + systemd).
		output := r.FormValue("output")
		if output == "" {
			output = "/etc/" + project.Slug + ".env"
		}
		reloadCmd := r.FormValue("reload_cmd")
		if reloadCmd == "" {
			reloadCmd = "systemctl restart " + project.Slug
		}
		requiredKeys := strings.TrimSpace(r.FormValue("required_keys"))

		endpoint := strings.TrimRight(deps.PublicURL, "/") + "/render"
		script, err := RenderAgentScript(AgentScriptParams{
			Project:      project.Slug,
			Env:          env.Slug,
			GeneratedAt:  time.Unix(deps.now(), 0).UTC().Format(time.RFC3339),
			Token:        plain,
			Endpoint:     endpoint,
			Output:       output,
			ReloadCmd:    reloadCmd,
			RequiredKeys: requiredKeys,
		})
		if err != nil {
			httpError(w, http.StatusInternalServerError, "render script")
			return
		}

		scriptPath := "/usr/local/bin/keep-agent-" + project.Slug + "-" + env.Slug + ".sh"
		unit := SystemdUnitFor(project.Slug, env.Slug, scriptPath)
		timer := SystemdTimerFor(project.Slug, env.Slug)
		bootstrap := BootstrapInstallCommand(project.Slug, env.Slug, string(script), unit, timer)

		renderHTML(w, deps, "token_minted", map[string]any{
			"Title":            "Token minted",
			"Session":          sessionFor(r),
			"Project":          project,
			"Env":              env,
			"TokenID":          row.ID,
			"Plaintext":        plain,
			"AgentScript":      string(script),
			"SystemdUnit":      unit,
			"SystemdTimer":     timer,
			"BootstrapCommand": bootstrap,
		})
	}
}

func tokenScriptHandler(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		project, env, ok := loadProjectEnv(deps, r)
		if !ok {
			http.NotFound(w, r)
			return
		}
		id, err := strconv.Atoi(chi.URLParam(r, "id"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		tok, err := deps.Stores.Tokens.Get(r.Context(), id)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if tok.EnvID != env.ID {
			http.NotFound(w, r)
			return
		}
		plain, ok := inMemoryTokenCache.get(id)
		if !ok {
			http.Error(w, "script unavailable: re-mint a new token to download", http.StatusGone)
			return
		}

		endpoint := strings.TrimRight(deps.PublicURL, "/") + "/render"
		script, err := RenderAgentScript(AgentScriptParams{
			Project:     project.Slug,
			Env:         env.Slug,
			GeneratedAt: time.Unix(deps.now(), 0).UTC().Format(time.RFC3339),
			Token:       plain,
			Endpoint:    endpoint,
			Output:      "/etc/" + project.Slug + ".env",
			ReloadCmd:   "systemctl restart " + project.Slug,
		})
		if err != nil {
			httpError(w, http.StatusInternalServerError, "render script")
			return
		}

		w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="keep-agent-`+project.Slug+`-`+env.Slug+`.sh"`)
		_, _ = w.Write(script)
	}
}

func tokenRevokeHandler(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		project, env, ok := loadProjectEnv(deps, r)
		if !ok {
			http.NotFound(w, r)
			return
		}
		id, err := strconv.Atoi(chi.URLParam(r, "id"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		ctx := r.Context()
		tok, err := deps.Stores.Tokens.Get(ctx, id)
		if err != nil || tok.EnvID != env.ID {
			http.NotFound(w, r)
			return
		}
		if err := deps.Stores.Tokens.Revoke(ctx, id); err != nil {
			httpError(w, http.StatusInternalServerError, "revoke")
			return
		}
		_ = deps.Stores.Audit.Append(ctx, store.AuditEntry{
			At:     deps.now(),
			Actor:  "user:1",
			Action: "token.revoke",
			Target: "tokens/" + strconv.Itoa(id),
		})
		http.Redirect(w, r, "/projects/"+project.Slug+"/envs/"+env.Slug+"/tokens", http.StatusSeeOther)
	}
}

func parseExpiry(s string) time.Duration {
	switch s {
	case "1h":
		return time.Hour
	case "24h":
		return 24 * time.Hour
	case "7d":
		return 7 * 24 * time.Hour
	case "30d":
		return 30 * 24 * time.Hour
	default:
		return 0
	}
}

// quiet sql.ErrNoRows hint while keeping the import obvious. Used in places
// where store helpers wrap and re-export this sentinel.
var _ = sql.ErrNoRows
