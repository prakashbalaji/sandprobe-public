package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"sandprobe/internal/obs"
)

// UX-6, UX-7, KND-3: the summary's top finding and every walker finding carry their evidence class: "proof" only for a
// proven, non-potential finding, and "a sign we saw, not confirmed" for an indicator, a potential chain or a class the
// report doesn't name; an unknown check has none (sandprobe-codex's review of #50, finding 3).
func TestEvidenceClassInSummaryAndWalker(t *testing.T) {
	vibe := loadReportJSON(t, "../../demo/reports/vibe.json")
	caps := termCaps{width: 80}
	if got := renderResult(vibe, "", true, caps); !strings.Contains(got, "CHAIN CHN-1 · CRITICAL · proof\n") {
		t.Errorf("proven chain lost its class:\n%s", got)
	}

	// Indicator only: AMP-4's control socket, never connected.
	ind := loadReportJSON(t, "../../demo/reports/vibe.json")
	for _, f := range ind.Findings {
		if f.ID == "AMP-4" {
			ind.Findings = append(ind.Findings[:0], f)
			break
		}
	}
	got := renderResult(ind, "", true, caps)
	if !strings.Contains(got, "TOP FINDING AMP-4 · HIGH · a sign we saw, not confirmed\n") || strings.Contains(got, "· proof") {
		t.Errorf("indicator-only finding reads as proof:\n%s", got)
	}

	pot := loadReportJSON(t, "../../demo/reports/vibe.json")
	pot.Findings[0].Potential = true
	unnamed := loadReportJSON(t, "../../demo/reports/vibe.json")
	unnamed.Findings[0].Class = ""
	for name, d := range map[string]struct {
		d    string
		want string
	}{"potential": {renderResult(pot, "", true, caps), "POTENTIAL CHAIN CHN-1 · CRITICAL · a sign we saw, not confirmed\n"},
		"no class": {renderResult(unnamed, "", true, caps), "CHAIN CHN-1 · CRITICAL · a sign we saw, not confirmed\n"}} {
		if !strings.Contains(d.d, d.want) {
			t.Errorf("%s: want %q in:\n%s", name, d.want, d.d)
		}
	}

	// The walker: CHN-1 proof, SEC-1 an indicator, and an unknown check with no class line.
	walk := loadReportJSON(t, "../../demo/reports/vibe.json")
	for i := range walk.Checks {
		if walk.Checks[i].ID == "EGR-4" {
			walk.Checks[i].Result, walk.Checks[i].Reason = obs.Unknown, "timed out"
		}
	}
	items := walkerItems(walk)
	keys := []string{}
	for range items {
		keys = append(keys, "j")
	}
	var out bytes.Buffer
	runKeyLoop(&oneKeyReader{keys: append(keys, "q")}, &out, walk, "", true, termCaps{tty: true, width: 80}, walkerHooks{})
	s := out.String()
	assertWidthAndNoLetter(t, "walker classes", s, 80)
	for _, want := range []string{"CHN-1 CRITICAL ", "    Class: proof\n", "SEC-1 HIGH ", "    Class: a sign we saw, not confirmed\n", "EGR-4 UNKNOWN"} {
		if !strings.Contains(s, want) {
			t.Errorf("walker missing %q", want)
		}
	}
	unknown := s[strings.Index(s, "EGR-4 UNKNOWN"):]
	if strings.Contains(unknown[:strings.Index(unknown, "[j/k]")], "Class:") {
		t.Errorf("an unknown check claims an evidence class:\n%s", unknown)
	}
	if n := strings.Count(s, "    Class: "); n != len(walk.Findings) {
		t.Errorf("%d class lines for %d findings", n, len(walk.Findings))
	}
}

// UX-7: Esc or b inside a finding goes back to the summary; only Esc on the summary (or q) quits (finding 4).
func TestEscGoesBackFromAFinding(t *testing.T) {
	vibe := loadReportJSON(t, "../../demo/reports/vibe.json")
	for _, back := range []string{"\x1b", "b"} {
		for _, quit := range []string{"\x1b", "q"} {
			r := &oneKeyReader{keys: []string{"\n", back, quit, "j"}}
			var out bytes.Buffer
			runKeyLoop(r, &out, vibe, "", true, termCaps{tty: true, width: 80}, walkerHooks{})
			s := out.String()
			if r.i != 3 || strings.Count(s, "[1/16] CHN-1") != 1 || strings.Count(s, "SCORE 1/6") != 1 || strings.Count(s, "[Enter] walk (16)") != 2 {
				t.Errorf("Enter, %q, %q: read %d keys; want the finding, then the summary and its bar again, then quit:\n%s", back, quit, r.i, s)
			}
		}
	}
}

// UX-9: every line `sandprobe scorecard` prints stays within 80 columns for every saved report, the coverage
// sentence, row details, statement and saved-report note included; under LC_ALL=C it is ASCII only (finding 5).
func TestScorecardFitsEightyColumns(t *testing.T) {
	reports, _ := filepath.Glob("../../demo/reports/*.json")
	more, _ := filepath.Glob("../../test/reports/*.json")
	reports = append(reports, more...)
	if len(reports) < 5 {
		t.Fatalf("saved reports: %v", reports)
	}
	for _, locale := range []string{"en_US.UTF-8", "C"} {
		t.Setenv("LC_ALL", locale)
		for _, in := range reports {
			var out, errs bytes.Buffer
			if code := run([]string{"scorecard", in}, &out, &errs); code != exitGraded && code != exitPartial {
				t.Fatalf("%s: exit %d %s", in, code, errs.String())
			}
			for i, line := range strings.Split(out.String(), "\n") {
				if cols := displayWidth(line); cols > 80 {
					t.Errorf("%s %s: line %d is %d columns: %q", locale, filepath.Base(in), i+1, cols, line)
				}
				if locale == "C" && strings.ContainsFunc(line, func(r rune) bool { return r > 127 }) {
					t.Errorf("%s: non-ASCII under LC_ALL=C: %q", filepath.Base(in), line)
				}
			}
		}
	}
}
