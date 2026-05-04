// Package web embeds the built Tailwind CSS so the keep binary stays a single
// file. Run `npm --prefix web run build` to regenerate dist/keep.css.
package web

import (
	"embed"
	"io/fs"
)

//go:embed dist
var distFS embed.FS

// Dist returns a filesystem rooted at the dist directory (so callers see
// "keep.css" at the root, not "dist/keep.css").
func Dist() fs.FS {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		panic("web: dist fs: " + err.Error())
	}
	return sub
}
