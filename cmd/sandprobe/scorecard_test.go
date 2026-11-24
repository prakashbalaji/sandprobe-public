package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"sandprobe/internal/host"
	"sandprobe/internal/obs"
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

func TestPrintableEscapesUnicodeFormatControls(t *testing.T) {
	for _, r := range []rune{0x061c, 0x200b, 0x200e, 0x200f, 0x202a, 0x202e, 0x2066, 0x2069, 0xfeff} {
		raw := "before" + string(r) + "after"
		got := printable(raw)
		if strings.ContainsRune(got, r) || !strings.Contains(got, `\u`) {
			t.Fatalf("format control U+%04X remains active: %q", r, got)
		}
	}
	if got := printable("plain café 日本語 🚀"); got != "plain café 日本語 🚀" {
		t.Fatalf("ordinary Unicode changed: %q", got)
	}
	if got := printable("x\x1b\n\u2028\u2029y"); strings.ContainsAny(got, "\x1b\n\u2028\u2029") {
		t.Fatal("existing control escaping regressed")
	}
}

// SCR-2, UX-9: scorecard on saved sandprobe/1 and sandprobe/2 reports labels a green row with no conclusive check
// "◌ GREEN · NOT PROVEN" (ASCII under a C locale) and flags it in -o json; proven green rows are unchanged; every
// category row fits 80 columns.
func TestScorecardGreenNotProven(t *testing.T) {
	t.Setenv("LC_ALL", "")
	t.Setenv("LC_CTYPE", "")
	t.Setenv("LANG", "en_US.UTF-8")
	optInSEC4 := host.ExecExclusions()
	delete(optInSEC4, "SEC-4") // run exec -provider-endpoints SEC-4: AMP-7 stays an opt_in skip
	v2 := skipSaved(t, "exec", host.Options{Excluded: optInSEC4, ExcludedKind: obs.SkipOptIn})
	if b, _ := os.ReadFile(v2); !bytes.Contains(b, []byte(`"schema":"sandprobe/2"`)) {
		t.Fatal("the run exec report doesn't declare sandprobe/2")
	}
	const cloud = "  ◌ GREEN · NOT PROVEN  Cloud access  Can it use your cloud identity?\n"
	for name, tc := range map[string]struct {
		path   string
		proven []string
	}{
		"sandprobe/1 demo vibe":                {"../../demo/reports/vibe.json", nil},
		"sandprobe/1 egress-refused":           {"../../test/reports/egress-refused.json", []string{"Exfiltration", "Containment"}},
		"sandprobe/2 run exec, SEC-4 opted in": {v2, []string{"Exfiltration", "Containment"}},
	} {
		var out, errs bytes.Buffer
		if code := run([]string{"scorecard", tc.path}, &out, &errs); code != exitGraded {
			t.Fatalf("%s: exit %d, %s", name, code, errs.String())
		}
		s := out.String()
		if !strings.Contains(s, cloud) || strings.Contains(s, "● GREEN  Cloud access") {
			t.Errorf("%s: no not-proven Cloud access row in:\n%s", name, s)
		}
		for _, p := range tc.proven {
			if !strings.Contains(s, "  ● GREEN  "+p+" ") {
				t.Errorf("%s: proven %s isn't plain GREEN in:\n%s", name, p, s)
			}
		}
		out.Reset()
		if code := run([]string{"scorecard", tc.path, "-o", "json"}, &out, &errs); code != exitGraded {
			t.Fatalf("%s: json exit %d", name, code)
		}
		var c report.Card
		if err := json.Unmarshal(out.Bytes(), &c); err != nil {
			t.Fatal(err)
		}
		for _, r := range c.Rows {
			if r.GreenNotProven != (r.Name == "Cloud access") || r.GreenNotProven && !r.Green {
				t.Errorf("%s: -o json %s: %+v", name, r.Name, r)
			}
		}
		if !bytes.Contains(out.Bytes(), []byte(`"green_not_proven": true`)) {
			t.Errorf("%s: -o json has no green_not_proven field", name)
		}
	}

	t.Setenv("LC_ALL", "C")
	var out, errs bytes.Buffer
	run([]string{"scorecard", "../../demo/reports/vibe.json"}, &out, &errs)
	if s := out.String(); !strings.Contains(s, "  o GREEN . NOT PROVEN  Cloud access  Can it use your cloud identity?\n") || strings.Contains(s, "◌") {
		t.Errorf("C locale: no ASCII not-proven row in:\n%s", s)
	}

	t.Setenv("LC_ALL", "")
	d := report.Doc{Grade: report.Grade{Valid: true}}
	for _, category := range report.Categories {
		for _, id := range category.Checks {
			d.Checks = append(d.Checks, report.Check{ID: id, Result: "not_found"})
		}
	}
	out.Reset()
	printCard(opts{stdout: &out}, report.Score(d), "")
	s := out.String()
	if strings.Count(s, "  ◌ GREEN · NOT PROVEN  ") != 6 || !strings.Contains(s, "Score 6/6") {
		t.Fatalf("every row not proven:\n%s", s)
	}
	if !strings.Contains(s, "  ◌ GREEN · NOT PROVEN  Persistence\n"+strings.Repeat(" ", 25)+"Can it leave something for the next session?\n") {
		t.Errorf("the long question didn't move under its row:\n%s", s)
	}
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, "  ◌ ") || strings.HasPrefix(line, strings.Repeat(" ", 25)+"Can it") {
			if n := utf8.RuneCountInString(line); n > 80 {
				t.Errorf("%d columns: %q", n, line)
			}
		}
	}
	out.Reset()
	printCard(opts{stdout: &out}, report.Score(report.Doc{}), "")
	if strings.Contains(out.String(), "NOT PROVEN") {
		t.Error("an invalid run shows the not-proven label")
	}
}
