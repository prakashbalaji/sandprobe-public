package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"sandprobe/internal/catalog"
	"sandprobe/internal/host"
	"sandprobe/internal/obs"
	"sandprobe/internal/report"
)

var ansiSGR = regexp.MustCompile(`\x1b\[[0-9;]*m`)
var letterGradePattern = regexp.MustCompile(`(?i)\bgrade\s+[ABCDF]\b`)

func assertWidthAndNoLetter(t *testing.T, label, rendered string, maxCols int) {
	t.Helper()
	if letterGradePattern.MatchString(rendered) {
		t.Errorf("%s: rendered output mentions a letter grade:\n%s", label, rendered)
	}
	for i, rawLine := range strings.Split(rendered, "\n") {
		plain := ansiSGR.ReplaceAllString(rawLine, "")
		if cols := utf8.RuneCountInString(plain); cols > maxCols {
			t.Errorf("%s: line %d is %d columns (> %d): %q", label, i+1, cols, maxCols, plain)
		}
	}
}

func loadReportJSON(t *testing.T, path string) report.Doc {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var d report.Doc
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

// UX-6, UX-9, AGT-1: non-TTY result output matches the golden file byte for byte, carries zero ANSI escapes,
// zero key bar, and no letter grade, with every line <= 80 columns.
func TestResultGoldenNonTTY(t *testing.T) {
	vibe := loadReportJSON(t, "../../demo/reports/vibe.json")
	got := renderResult(vibe, "sandprobe-reports/sandprobe-docker-"+vibe.Run.ID, true, termCaps{width: 80})
	if strings.Contains(got, "\x1b") {
		t.Fatalf("non-TTY output contains ESC sequence: %q", got)
	}
	if strings.Contains(got, "[Enter]") || strings.Contains(got, "[q] quit") {
		t.Fatalf("non-TTY output contains interactive key bar:\n%s", got)
	}
	assertWidthAndNoLetter(t, "vibe-golden", got, 80)

	goldenPath := filepath.Join("testdata", "vibe_result.golden")
	if os.Getenv("SANDPROBE_UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenPath, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("missing golden file %s: %v", goldenPath, err)
	}
	if got != string(want) {
		t.Fatalf("golden mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, string(want))
	}
}

// UX-6, SCR-2, OUT-4: every run state renders accurately and stays within <= 80 columns (and narrower TTY widths).
func TestResultStatesAndWidth(t *testing.T) {
	vibe := loadReportJSON(t, "../../demo/reports/vibe.json")
	hardened := loadReportJSON(t, "../../demo/reports/hardened.json")
	canaryDown := loadReportJSON(t, "../../test/reports/canary-down.json")

	noCanary := canaryDown
	noCanary.Run.NoCanary = true

	spritesPath := skipSaved(t, "sprites", host.Options{Excluded: host.SpritesExclusions(), ExcludedKind: obs.SkipProviderTerms})
	spritesDoc := loadReportJSON(t, spritesPath)

	cleanAllProven := doc("A", true, true)
	cleanAllProven.Run.Box.Name = "sandprobe-clean-box"
	cleanAllProven.Identity = &obs.Identity{UID: 1000}
	cleanAllProven.Cleanup.Outcome = "deleted and confirmed gone"

	invalidDoc := doc("", false, false)
	invalidDoc.Grade.Invalid = "probe SHA-256 mismatch on returned observations"
	invalidDoc.Cleanup.Outcome = "deleted and confirmed gone"

	cases := []struct {
		name     string
		d        report.Doc
		cleaned  bool
		mustHave []string
		forbid   []string
	}{
		{
			name:    "valid 1/6 with chain and receipts",
			d:       vibe,
			cleaned: true,
			mustHave: []string{
				"SCORE 1/6  1 of 6 categories green",
				"✗ RED    Secrets",
				"◌ GREEN · NOT PROVEN  Cloud access",
				"CHAIN CHN-1 · CRITICAL",
				"Canary receipts: 6",
				"Fix first:",
				"✓ Cleanup",
			},
		},
		{
			name:    "clean 6/6 all proven",
			d:       cleanAllProven,
			cleaned: true,
			mustHave: []string{
				"SCORE 6/6  6 of 6 categories green",
				"✓ GREEN  Cloud access",
				"No findings across tested checks.",
			},
			forbid: []string{"GREEN · NOT PROVEN", "✗ RED"},
		},
		{
			name:    "hardened 6/6 with Green not proven Cloud access",
			d:       hardened,
			cleaned: true,
			mustHave: []string{
				"SCORE 6/6  6 of 6 categories green",
				"✓ GREEN  Secrets",
				"◌ GREEN · NOT PROVEN  Cloud access",
				"not proven: cloud metadata credentials",
			},
		},
		{
			name:    "x/5 not applicable provider terms",
			d:       spritesDoc,
			cleaned: true,
			mustHave: []string{
				"SCORE 2/5  2 of 5 categories green",
				"Cloud access isn't counted",
				"– N/A    Cloud access",
			},
		},
		{
			name:    "incomplete canary down",
			d:       canaryDown,
			cleaned: true,
			mustHave: []string{
				"Incomplete:",
				"Couldn't prove:",
			},
		},
		{
			name:    "no-canary incomplete",
			d:       noCanary,
			cleaned: true,
			mustHave: []string{
				"Not tested: run without a canary",
				"Run without -no-canary to test exfiltration routes.",
			},
		},
		{
			name:    "invalid run has no score, rows or counts",
			d:       invalidDoc,
			cleaned: true,
			mustHave: []string{
				"SCORE none  Invalid run",
				"probe SHA-256 mismatch",
				"✓ Cleanup",
			},
			forbid: []string{"categories green", "Secrets", "Exfiltration", "checks conclusive"},
		},
		{
			name:    "unconfirmed cleanup loud warning",
			d:       cleanAllProven,
			cleaned: false,
			mustHave: []string{
				"✗ CLEANUP UNCONFIRMED (exit 7)",
			},
		},
	}

	for _, tc := range cases {
		for _, color := range []bool{false, true} {
			for _, width := range []int{80, 64} {
				got := renderResult(tc.d, "sandprobe-reports/sandprobe-test-r1", tc.cleaned, termCaps{color: color, width: width})
				assertWidthAndNoLetter(t, tc.name, got, width)
				plain := ansiSGR.ReplaceAllString(got, "")
				for _, want := range tc.mustHave {
					if !strings.Contains(plain, want) {
						t.Errorf("%s (color=%v width=%d): missing %q in:\n%s", tc.name, color, width, want, plain)
					}
				}
				for _, bad := range tc.forbid {
					if strings.Contains(plain, bad) {
						t.Errorf("%s (color=%v width=%d): unexpected %q in:\n%s", tc.name, color, width, bad, plain)
					}
				}
			}
		}
	}
}

// UX-6, UX-9, SCR-3: hostile control characters, ESC sequences, CR/LF and Unicode line separators in box/report
// fields are escaped before terminal emission, and category rows carry zero box-controlled strings.
func TestTerminalInjectionEscaped(t *testing.T) {
	payload := "evil\x1b[2J\x1b]0;pwned\x07\r\nline2\u2028sep\u2029end"
	d := doc("D", true, true)
	d.Run.Provider = "docker\x1b[31m"
	d.Run.Box.Name = payload
	for i := range d.Checks {
		if d.Checks[i].ID == "SEC-1" {
			d.Checks[i].Title = "BOX-SENTINEL-" + payload
			d.Checks[i].Evidence = "BOX-SENTINEL-" + payload
			d.Checks[i].Reason = "BOX-SENTINEL-" + payload
		}
	}
	d.Findings = []report.Finding{{
		ID:       "SEC-1",
		Severity: "high\x1b[2J",
		Title:    payload,
		Gets:     payload,
		Fix:      payload,
	}}
	d.Receipts = []obs.Receipt{{Nonce: "n1", Proto: "tcp\x1b[2J", Port: 443}}
	d.Cleanup.Outcome = payload

	got := renderResult(d, "sandprobe-reports/out\x1b[2J", false, termCaps{width: 80})
	for _, r := range got {
		if r == '\n' {
			continue
		}
		if unicode.IsControl(r) || r == 0x2028 || r == 0x2029 {
			t.Fatalf("unescaped control rune U+%04X in output:\n%q", r, got)
		}
	}
	if !strings.Contains(got, `\u001b[2J`) || !strings.Contains(got, `\u2028`) {
		t.Fatalf("expected escaped sequences in output:\n%s", got)
	}
	for _, line := range strings.Split(got, "\n") {
		if strings.Contains(line, "Secrets") && strings.Contains(line, "BOX-SENTINEL") {
			t.Fatalf("box string leaked into category row: %q", line)
		}
	}

	// Invalid run reason also escaped.
	inv := doc("", false, false)
	inv.Grade.Invalid = payload
	invGot := renderResult(inv, "sandprobe-reports/inv", true, termCaps{width: 80})
	for _, r := range invGot {
		if r != '\n' && (unicode.IsControl(r) || r == 0x2028 || r == 0x2029) {
			t.Fatalf("unescaped control rune U+%04X in invalid output:\n%q", r, invGot)
		}
	}
}

// UX-9: NO_COLOR, TERM=dumb, LC_ALL=C (ASCII), and SANDPROBE_REDUCED_MOTION behave deterministically.
func TestModeTable(t *testing.T) {
	vibe := loadReportJSON(t, "../../demo/reports/vibe.json")

	t.Run("NO_COLOR", func(t *testing.T) {
		t.Setenv("NO_COLOR", "1")
		t.Setenv("TERM", "xterm-256color")
		caps := detectTermCaps(os.Stdout, true)
		if caps.color {
			t.Fatal("NO_COLOR=1 left color enabled")
		}
		got := renderResult(vibe, "out/r", true, caps)
		if strings.Contains(got, "\x1b") {
			t.Fatalf("NO_COLOR output contains ANSI escape: %q", got)
		}
	})

	t.Run("TERM=dumb", func(t *testing.T) {
		t.Setenv("NO_COLOR", "")
		t.Setenv("TERM", "dumb")
		caps := detectTermCaps(os.Stdout, true)
		if caps.color || caps.tty || !caps.reducedMotion {
			t.Fatalf("TERM=dumb caps = %+v, want color=false tty=false reducedMotion=true", caps)
		}
	})

	t.Run("LC_ALL=C ASCII", func(t *testing.T) {
		t.Setenv("LC_ALL", "C")
		caps := detectTermCaps(&bytes.Buffer{}, false)
		if !caps.ascii {
			t.Fatal("LC_ALL=C did not enable ASCII mode")
		}
		got := renderResult(vibe, "out/r", true, caps)
		if !strings.Contains(got, "o GREEN . NOT PROVEN  Cloud access") || !strings.Contains(got, "x RED    Secrets") {
			t.Fatalf("ASCII symbols/words missing:\n%s", got)
		}
		for _, r := range got {
			if r > 127 {
				t.Fatalf("non-ASCII rune %q (U+%04X) in LC_ALL=C output:\n%s", r, r, got)
			}
		}
		var cardOut bytes.Buffer
		printCard(opts{stdout: &cardOut}, report.Score(vibe), "")
		if !strings.Contains(cardOut.String(), "o GREEN . NOT PROVEN  Cloud access") {
			t.Fatalf("printCard ASCII missing GREEN . NOT PROVEN:\n%s", cardOut.String())
		}
		for _, r := range cardOut.String() {
			if r > 127 {
				t.Fatalf("non-ASCII rune %q in printCard LC_ALL=C output", r)
			}
		}
	})

	t.Run("SANDPROBE_REDUCED_MOTION", func(t *testing.T) {
		t.Setenv("SANDPROBE_REDUCED_MOTION", "1")
		caps := detectTermCaps(&bytes.Buffer{}, false)
		if !caps.reducedMotion {
			t.Fatal("SANDPROBE_REDUCED_MOTION=1 did not enable reducedMotion")
		}
	})
}

// UX-5: live phases match each adapter's plan (no reset on Nitro/exec/kubernetes; no canary under -no-canary;
// retain on Baseten -keep-sandbox), and non-TTY stderr writes plain append-only lines with escaped text.
func TestLivePhasesFromPlan(t *testing.T) {
	ids := func(ps []livePhase) []string {
		out := make([]string, len(ps))
		for i, p := range ps {
			out[i] = p.ID
		}
		return out
	}
	cases := []struct {
		provider    string
		noCanary    bool
		keepSandbox bool
		want        []string
	}{
		{"docker", false, false, []string{"network", "canary", "box", "probe", "reset", "delete"}},
		{"sprites", false, false, []string{"canary", "box", "probe", "reset", "delete"}},
		{"aws-nitro", false, false, []string{"canary", "box", "probe", "delete"}},
		{"e2b", false, false, []string{"canary", "box", "probe", "delete"}},
		{"kubernetes", false, false, []string{"canary", "box", "probe", "delete"}},
		{"kubernetes", true, false, []string{"box", "probe", "delete"}},
		{"exec", false, false, []string{"canary", "preflight", "probe", "cleanup"}},
		{"exec", true, false, []string{"preflight", "probe", "cleanup"}},
		{"baseten", false, true, []string{"canary", "box", "probe", "retain"}},
	}
	for _, tc := range cases {
		got := ids(livePhasesFor(tc.provider, tc.noCanary, tc.keepSandbox))
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s (noCanary=%v keep=%v): got %v, want %v", tc.provider, tc.noCanary, tc.keepSandbox, got, tc.want)
		}
	}

	var stderr bytes.Buffer
	lv := newLive(opts{out: "text"}, &stderr, "aws-nitro", livePhasesFor("aws-nitro", false, false))
	lv.phase("box", "pod sandprobe-1\x1b[2J ready")
	lv.close(true)
	if strings.Contains(stderr.String(), "\x1b") || !strings.Contains(stderr.String(), `· pod sandprobe-1\u001b[2J ready`) {
		t.Fatalf("non-TTY liveTracker output unsafe or unexpected: %q", stderr.String())
	}

	var jsonStderr bytes.Buffer
	jlv := newLive(opts{out: "json"}, &jsonStderr, "aws-nitro", livePhasesFor("aws-nitro", false, false))
	jlv.phase("box", "quiet")
	jlv.close(true)
	if jsonStderr.Len() != 0 {
		t.Fatalf("-o json emitted progress on stderr: %q", jsonStderr.String())
	}
}

// UX-7, AGT-1: finish never blocks or reads stdin on non-TTY stdout, and runKeyLoop steps through findings,
// explains checks, copies fixes, opens the report, and exits cleanly on q or Esc.
func TestWalkerKeysNeverHangNonTTY(t *testing.T) {
	vibe := loadReportJSON(t, "../../demo/reports/vibe.json")
	dir := t.TempDir()
	var nonTTYOut bytes.Buffer
	code, err := finish(opts{out: "text", stdout: &nonTTYOut}, runFlags{outDir: dir, theme: "graphite"}, vibe, true)
	if err != nil || code != exitGraded {
		t.Fatalf("finish non-TTY: code=%d err=%v", code, err)
	}
	if strings.Contains(nonTTYOut.String(), "[Enter]") {
		t.Fatalf("non-TTY finish printed interactive key bar:\n%s", nonTTYOut.String())
	}

	var opened, copied string
	hooks := walkerHooks{
		open: func(p string) error { opened = p; return nil },
		copy: func(s string) error { copied = s; return nil },
	}
	var loopOut bytes.Buffer
	// Feed one keypress per Read via a deterministic key reader.
	runKeyLoop(&oneKeyReader{keys: []string{"\n", "j", "e", "c", "o", "b", "q"}}, &loopOut, vibe, "out/rep", true, termCaps{tty: true, width: 80}, hooks)

	got := loopOut.String()
	assertWidthAndNoLetter(t, "walker", got, 80)
	for _, want := range []string{
		"[Enter] walk (16)",
		"[1/16] CHN-1",
		"[2/16] SEC-1",
		"SEC-1 Secret-shaped names in the agent's environment",
		"Copied fix for SEC-1",
		"Opened out/rep.html",
		"SCORE 1/6",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("walker output missing %q:\n%s", want, got)
		}
	}
	if opened != "out/rep.html" {
		t.Errorf("open hook got %q", opened)
	}
	if !strings.Contains(copied, "Keep credentials out of the agent's environment") {
		t.Errorf("copy hook got %q", copied)
	}

	// Esc exits immediately too.
	var escOut bytes.Buffer
	runKeyLoop(&oneKeyReader{keys: []string{"\x1b"}}, &escOut, vibe, filepath.Join(dir, "rep"), true, termCaps{tty: true, width: 80}, hooks)
	if !strings.Contains(escOut.String(), "[q] quit") {
		t.Errorf("Esc walker did not render initial bar: %q", escOut.String())
	}
}

type oneKeyReader struct {
	keys []string
	i    int
}

func (r *oneKeyReader) Read(p []byte) (int, error) {
	if r.i >= len(r.keys) {
		return 0, os.ErrClosed
	}
	n := copy(p, r.keys[r.i])
	r.i++
	return n, nil
}

// OUT-4: -min accepts 0..6 and full, enforces 7 > 6 > 5 > 0 exit precedence, and refuses retired letter grades.
func TestMinScoreGate(t *testing.T) {
	fiveOfSix := doc("C", true, true) // 5/6 green
	sixOfSix := doc("A", true, true)  // 6/6 green

	// Build a 5/5 clean Sprites doc (Cloud access not applicable).
	fiveOfFive := doc("A", true, true)
	fiveOfFive.Run.Provider = "sprites"
	fiveOfFive.Manifest.SkipKinds = map[string]string{"SEC-4": obs.SkipProviderTerms, "AMP-7": obs.SkipProviderTerms}
	fiveOfFive.Manifest.Skipped = map[string]string{"SEC-4": "terms", "AMP-7": "terms"}
	for i := range fiveOfFive.Checks {
		if fiveOfFive.Checks[i].ID == "SEC-4" || fiveOfFive.Checks[i].ID == "AMP-7" {
			fiveOfFive.Checks[i].Result = obs.Skipped
			fiveOfFive.Checks[i].Reason = "terms"
		}
	}
	if c := report.Score(fiveOfFive); c.Score != 5 || c.Of != 5 {
		t.Fatalf("fiveOfFive setup: got %d/%d", c.Score, c.Of)
	}

	gateCases := []struct {
		name    string
		d       report.Doc
		cleaned bool
		min     string
		want    int
	}{
		{"5/6 meets -min 5", fiveOfSix, true, "5", exitGraded},
		{"5/6 fails -min 6", fiveOfSix, true, "6", exitBelowMin},
		{"5/6 fails -min full", fiveOfSix, true, "full", exitBelowMin},
		{"6/6 meets -min full", sixOfSix, true, "full", exitGraded},
		{"6/6 meets -min FULL", sixOfSix, true, "FULL", exitGraded},
		{"5/5 meets -min full", fiveOfFive, true, "full", exitGraded},
		{"5/5 fails -min 6", fiveOfFive, true, "6", exitBelowMin},
		{"0/6 meets -min 0", doc("F", true, true), true, "0", exitGraded},
		{"incomplete below -min exits 6 over 5", doc("D", true, false), true, "5", exitBelowMin},
		{"incomplete meeting -min exits 5", doc("C", true, false), true, "3", exitPartial},
		{"invalid never exits 6, exits 5", doc("", false, false), true, "6", exitPartial},
		{"unconfirmed cleanup exits 7 over 6", fiveOfSix, false, "6", exitCleanup},
	}
	for _, tc := range gateCases {
		if got := exitFor(tc.d, tc.cleaned, tc.min); got != tc.want {
			t.Errorf("%s: exitFor = %d, want %d", tc.name, got, tc.want)
		}
	}

	// Retired letters and out-of-range values are refused with usage exit 2 before any provider runs.
	for _, bad := range []string{"A", "B", "C", "D", "F", "a", "-1", "7", "10", "all"} {
		var out, errs bytes.Buffer
		code := run([]string{"run", "sprites", "-min", bad, "-o", "json"}, &out, &errs)
		if code != exitUsage || !strings.Contains(out.String(), `"error": "usage"`) || !strings.Contains(out.String(), "-min 6") {
			t.Errorf("-min %q: code=%d out=%s", bad, code, out.String())
		}
	}
	// Ensure every catalog check still maps cleanly in explain cards.
	for _, id := range catalog.IDs() {
		card := renderExplainCard(id, 80, tuiStyle{})
		assertWidthAndNoLetter(t, "explain-"+id, card, 80)
	}
}
