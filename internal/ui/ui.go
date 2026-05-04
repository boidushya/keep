// Package ui parses the embedded HTML templates and serves the embedded CSS.
package ui

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"io/fs"
)

//go:embed layout.html components/*.html pages/*.html
var templatesFS embed.FS

// Templates parses every page into its own *template.Template, sharing the
// layout and component partials. The placeholder page is named "placeholder";
// real pages added later use their filename (without .html) as the page name.
type Templates struct {
	pages map[string]*template.Template
}

// New parses every page found under pages/. Each page must define a "body"
// block. The shared layout and component partials are merged in.
func New() (*Templates, error) {
	pages, err := fs.Glob(templatesFS, "pages/*.html")
	if err != nil {
		return nil, fmt.Errorf("ui: glob pages: %w", err)
	}

	out := &Templates{pages: make(map[string]*template.Template, len(pages))}
	for _, page := range pages {
		t := template.New("layout")

		// Layout (defines "layout") and shared components first.
		if _, err := t.ParseFS(templatesFS, "layout.html", "components/*.html"); err != nil {
			return nil, fmt.Errorf("ui: parse layout/components: %w", err)
		}
		// Then the page (defines "body" and possibly other partials).
		if _, err := t.ParseFS(templatesFS, page); err != nil {
			return nil, fmt.Errorf("ui: parse %s: %w", page, err)
		}

		name := pageName(page)
		out.pages[name] = t
	}
	return out, nil
}

// Render writes the named page to w. data must include a Title field and
// anything the page references.
func (t *Templates) Render(w io.Writer, name string, data any) error {
	tmpl, ok := t.pages[name]
	if !ok {
		return fmt.Errorf("ui: unknown page %q", name)
	}
	return tmpl.ExecuteTemplate(w, "layout", data)
}

func pageName(path string) string {
	// "pages/foo.html" -> "foo"
	const prefix = "pages/"
	const suffix = ".html"
	if len(path) > len(prefix)+len(suffix) {
		return path[len(prefix) : len(path)-len(suffix)]
	}
	return path
}
