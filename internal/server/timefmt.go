package server

import (
	"fmt"
	"time"
)

// relTime returns a short relative-time label like "3m ago", "2h ago", or
// "12d ago", computed from the provided "now". Used by the UI for the
// updated-at column in the secrets table.
func relTime(at, now int64) string {
	d := now - at
	switch {
	case d < 60:
		return "just now"
	case d < 60*60:
		return fmt.Sprintf("%dm ago", d/60)
	case d < 24*60*60:
		return fmt.Sprintf("%dh ago", d/(60*60))
	case d < 30*24*60*60:
		return fmt.Sprintf("%dd ago", d/(24*60*60))
	default:
		return time.Unix(at, 0).UTC().Format("2006-01-02")
	}
}
