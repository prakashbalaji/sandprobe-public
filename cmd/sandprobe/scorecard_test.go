package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sandprobe/internal/report"
)

// A saved report is untrusted: its provider and run ID name the page only when they're plain names (PR #40 review).
func TestReportFileNames(t *testing.T) {
	for _, tc := range []struct{ provider, id, want string }{
		{"docker", "r37cfbeb214de9729d4101b89", "sandprobe-docker-r37cfbeb214de9729d4101b89.html"},
		{"exe.dev", "r0123456789abcdef", "sandprobe-exe.dev-r0123456789abcdef.html"},
		{"../../tmp", "r0123456789abcdef", "sandprobe-report.html"},
		{"docker", "../../../escape", "sandprobe-report.html"},
		{"a/b", "r0123456789abcdef", "sandprobe-report.html"},
		{"docker", "r01234567/..", "sandprobe-report.html"},
		{"..", "r0123456789abcdef", "sandprobe-report.html"},
	} {
		if got := reportFile(tc.provider, tc.id); got != tc.want {
			t.Errorf("%q %q: got %q, want %q", tc.provider, tc.id, got, tc.want)
		}
	}
}

// writeInside never follows a symlink already at the destination, and never takes a path for a name.
func TestWriteInsideStaysInside(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	victim := filepath.Join(outside, "victim.html")
	os.WriteFile(victim, []byte("keep"), 0o644)
	os.Symlink(victim, filepath.Join(dir, "sandprobe-report.html"))
	if err := writeInside(dir, "sandprobe-report.html", []byte("overwritten")); err == nil {
		t.Fatal("wrote through a symlink")
	}
	if err := writeInside(dir, "../escape.html", []byte("x")); err == nil {
		t.Fatal("took a path for a name")
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Fatalf("the file outside -out changed: %q", b)
	}
}

// End to end: a saved report whose run ID is a path can't make scorecard -out write outside the directory.
func TestScorecardOutCannotEscape(t *testing.T) {
	b, err := os.ReadFile("../../demo/reports/vibe.json")
	if err != nil {
		t.Fatal(err)
	}
	var d report.Doc
	if err := json.Unmarshal(b, &d); err != nil || d.Run.ID == "" {
		t.Fatalf("the demo report: %v", err)
	}
	crafted := bytes.ReplaceAll(b, []byte(d.Run.ID), []byte("../../../escaped"))
	base := t.TempDir()
	in := filepath.Join(base, "crafted.json")
	os.WriteFile(in, crafted, 0o644)
	out := filepath.Join(base, "a", "b", "out")
	var stdout, stderr bytes.Buffer
	run([]string{"scorecard", in, "-out", out}, &stdout, &stderr)
	filepath.Walk(base, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.HasSuffix(p, ".html") && filepath.Dir(p) != out {
			t.Errorf("a page was written outside -out: %s", p)
		}
		return nil
	})
}

// Text from a saved report reaches the terminal with every control character escaped (PR #40 review).
func TestPrintCardEscapesStatement(t *testing.T) {
	var w bytes.Buffer
	printCard(opts{stdout: &w}, report.Card{Valid: true, Score: 6, Of: 6}, "graded\x1b[2J\x1b]0;spoofed\x07 and more")
	got := w.String()
	if strings.ContainsAny(got, "\x1b\x07 ") || !strings.Contains(got, `\u001b[2J`) {
		t.Fatalf("control characters reached the terminal: %q", got)
	}
}
