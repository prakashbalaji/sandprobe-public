package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// UX-8: -theme reaches the page, and with none the page is auto, which follows the viewer's system. dark is another
// name for graphite, and the page says graphite. A value that isn't a palette, the retired modern included, renders auto.
func TestThemeFlag(t *testing.T) {
	abs, _ := filepath.Abs("../../demo/reports/hardened.json") // a public report from the demo's Docker box
	for _, tc := range []struct {
		args []string
		want string
	}{{nil, "auto"}, {[]string{"-theme", "auto"}, "auto"}, {[]string{"-theme", "light"}, "light"}, {[]string{"-theme", "graphite"}, "graphite"},
		{[]string{"-theme", "mission"}, "mission"}, {[]string{"-theme", "dark"}, "graphite"}, {[]string{"-theme", "modern"}, "auto"}, {[]string{"-theme", "night"}, "auto"}} {
		pages := filepath.Join(t.TempDir(), "pages")
		var out, errb bytes.Buffer
		if code := run(append([]string{"scorecard", abs, "-out", pages}, tc.args...), &out, &errb); code != 0 {
			t.Fatalf("%v: code %d: %s", tc.args, code, errb.String())
		}
		m, _ := filepath.Glob(filepath.Join(pages, "sandprobe-*.html"))
		if len(m) != 1 {
			t.Fatalf("%v: want one page, got %v", tc.args, m)
		}
		page, err := os.ReadFile(m[0])
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(page), `<html lang="en" data-theme="`+tc.want+`">`) {
			t.Errorf("%v: want the page in %s", tc.args, tc.want)
		}
	}
}
