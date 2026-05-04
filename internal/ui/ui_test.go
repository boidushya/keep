package ui

import (
	"bytes"
	"strings"
	"testing"
)

func TestTemplatesRenderPlaceholder(t *testing.T) {
	t.Parallel()

	tt, err := New()
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := tt.Render(&buf, "placeholder", map[string]any{
		"Title":   "Home",
		"Session": nil,
	}); err != nil {
		t.Fatalf("render: %v", err)
	}

	html := buf.String()
	for _, want := range []string{
		"<title>Home · keep</title>",
		`class="keep-wordmark">keep</span>`,
		"is running.",
		`href="/static/keep.css"`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("expected %q in output, not present", want)
		}
	}
}
