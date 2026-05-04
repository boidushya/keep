package server

import (
	"net/http"
	"strconv"
	"strings"
)

const auditPageSize = 100

type auditFilter struct {
	Action string
	Actor  string
}

type auditRow struct {
	ID      int
	When    int64
	WhenRel string
	Actor   string
	Action  string
	Target  string
}

func auditHandler(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		filter := auditFilter{
			Action: strings.TrimSpace(r.URL.Query().Get("action")),
			Actor:  strings.TrimSpace(r.URL.Query().Get("actor")),
		}
		beforeID, _ := strconv.Atoi(r.URL.Query().Get("before_id"))

		// Pull more than page-size when filtering, since we filter in memory
		// (simpler than threading optional WHEREs through the store).
		fetch := auditPageSize
		if filter.Action != "" || filter.Actor != "" {
			fetch = auditPageSize * 5
		}

		entries, err := deps.Stores.Audit.List(ctx, fetch, beforeID)
		if err != nil {
			httpError(w, http.StatusInternalServerError, "list audit")
			return
		}

		now := deps.now()
		rows := make([]auditRow, 0, len(entries))
		for _, e := range entries {
			if filter.Action != "" && !strings.HasPrefix(e.Action, filter.Action) {
				continue
			}
			if filter.Actor != "" && e.Actor != filter.Actor {
				continue
			}
			rows = append(rows, auditRow{
				ID:      e.ID,
				When:    e.At,
				WhenRel: relTime(e.At, now),
				Actor:   e.Actor,
				Action:  e.Action,
				Target:  e.Target,
			})
			if len(rows) >= auditPageSize {
				break
			}
		}

		var nextBeforeID int
		if len(rows) == auditPageSize {
			nextBeforeID = rows[len(rows)-1].ID
		}

		renderHTML(w, deps, "audit", map[string]any{
			"Title":        "Audit log",
			"Session":      sessionFor(r),
			"Filter":       filter,
			"Entries":      rows,
			"NextBeforeID": nextBeforeID,
		})
	}
}
