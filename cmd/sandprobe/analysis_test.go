package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"sandprobe/internal/analysis"
	"sandprobe/internal/obs"
	"sandprobe/internal/report"
)

func TestOfflineCLI(t *testing.T) {
	const report = "../../test/reports/egress-open.json"  // complete
	const partial = "../../test/reports/canary-down.json" // incomplete: the canary was down
	for _, tc := range []struct {
		args     []string
		exit     int
		contains string
	}{
		{[]string{"profile", report, "-o", "json"}, 0, `"verification": "structural_only_unauthenticated"`},
		{[]string{"compare", report, report, "-o", "json"}, 0, `"no_observed_change": true`},
		{[]string{"compare", partial, partial, "-o", "json"}, 5, `"incomplete": true`},
		{[]string{"profile", "/dev/null", "-o", "json"}, 2, `report.input`},
		{[]string{"compare", report, "-o", "json"}, 2, `usage`},
		{[]string{"scorecard", report}, 0, "Score 2/6"},
		{[]string{"scorecard", report, "-o", "json"}, 0, `"of": 6`},
		{[]string{"scorecard", partial}, 5, "Score "},
		{[]string{"scorecard", "-o", "json"}, 2, `usage`},
	} {
		var out, err bytes.Buffer
		code := run(tc.args, &out, &err)
		if code != tc.exit || !bytes.Contains(append(out.Bytes(), err.Bytes()...), []byte(tc.contains)) {
			t.Errorf("args %v: code %d", tc.args, code)
		}
	}
}

// SCR-3: scorecard writes its page only to an explicit -out directory.
func TestScorecardWritesOnlyWithOut(t *testing.T) {
	const saved = "../../demo/reports/hardened.json" // a public report from the demo's Docker box
	abs, _ := filepath.Abs(saved)
	dir := t.TempDir()
	t.Chdir(dir)
	var out, errb bytes.Buffer
	if code := run([]string{"scorecard", abs}, &out, &errb); code != 0 {
		t.Fatalf("code %d: %s", code, errb.String())
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("wrote %d files without -out", len(entries))
	}
	pages := filepath.Join(dir, "pages")
	if code := run([]string{"scorecard", abs, "-out", pages}, &out, &errb); code != 0 {
		t.Fatalf("code %d: %s", code, errb.String())
	}
	if m, _ := filepath.Glob(filepath.Join(pages, "sandprobe-*.html")); len(m) != 1 {
		t.Fatalf("want one page in -out, got %v", m)
	}
}

func TestComparisonContextDoesNotHideFindings(t *testing.T) {
	// The same box, refused at its firewall, then open: six routes newly out, and nothing else changed.
	before := []string{"../../test/reports/egress-refused.json"}
	after := []string{"../../test/reports/egress-open.json"}
	b, e := os.ReadFile(after[0])
	if e != nil {
		t.Fatal(e)
	}
	var d report.Doc
	if e = json.Unmarshal(b, &d); e != nil {
		t.Fatal(e)
	}
	d.Run.Provider = "context-change-fixture"
	changed := filepath.Join(t.TempDir(), "changed.json")
	b, e = json.Marshal(d)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(changed, b, 0600); e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		path    string
		exit    int
		context bool
	}{{after[0], 6, false}, {changed, 5, true}} {
		var out, stderr bytes.Buffer
		code := run([]string{"compare", before[0], tc.path, "-o", "json"}, &out, &stderr)
		var result struct {
			Findings []string `json:"new_or_worse_findings"`
			Context  []string `json:"context_changes"`
			NoChange bool     `json:"no_observed_change"`
		}
		if e = json.Unmarshal(out.Bytes(), &result); e != nil {
			t.Fatal(e)
		}
		if code != tc.exit || len(result.Findings) != 6 || result.NoChange || ((len(result.Context) > 0) != tc.context) {
			t.Fatalf("unexpected comparison result, exit %d", code)
		}
	}
}

func TestComparisonRegressionExitIgnoresCHN2AndLifecycleNotes(t *testing.T) {
	before := []string{"../../test/reports/egress-refused.json"}
	after := []string{"../../test/reports/egress-open.json"}
	var docs [2]report.Doc
	for i, path := range []string{before[0], after[0]} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(data, &docs[i]); err != nil {
			t.Fatal(err)
		}
		docs[i].Grade.Notes = []string{"REF-2: same reference settings", "REF-3: same profile and image"}
	}
	docs[1].Grade.Notes = append(docs[1].Grade.Notes, "CHN-2: a root-equivalent amplifier", "lifecycle error: cleanup failed")
	dir := t.TempDir()
	for _, changedContext := range []bool{false, true} {
		if changedContext {
			docs[1].Grade.Notes[1] = "REF-3: different profile or image"
		}
		paths := []string{filepath.Join(dir, "before.json"), filepath.Join(dir, "after.json")}
		for i, path := range paths {
			data, err := json.Marshal(docs[i])
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
		}
		var out, stderr bytes.Buffer
		code := run([]string{"compare", paths[0], paths[1], "-o", "json"}, &out, &stderr)
		var result struct {
			Findings []string `json:"new_or_worse_findings"`
			Context  []string `json:"context_changes"`
		}
		if err := json.Unmarshal(out.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		want := 6
		if changedContext {
			want = 5
		}
		if code != want || len(result.Findings) != 6 || (len(result.Context) > 0) != changedContext {
			t.Fatalf("regression masked: exit=%d findings=%d context=%v", code, len(result.Findings), result.Context)
		}
	}
}

// compare's words lead with what it found: a regression always reads as worse, even beside an incomplete report, and
// an incomplete pair never reads as all clear.
func TestCompareVerdictWords(t *testing.T) {
	for _, tc := range []struct {
		a, b, want, never string
		exit              int
	}{
		{"../../demo/reports/hardened.json", "../../demo/reports/regressed.json", "Verdict: worse.", "no change", 6},
		{"../../test/reports/canary-down.json", "../../test/reports/canary-down.json", "wouldn't count either", "Verdict: no change", 5},
	} {
		var out, errb bytes.Buffer
		code := run([]string{"compare", tc.a, tc.b}, &out, &errb)
		if code != tc.exit || !strings.Contains(out.String(), tc.want) || strings.Contains(out.String(), tc.never) {
			t.Errorf("%s vs %s: exit %d, output %q", tc.a, tc.b, code, out.String())
		}
	}
}

// comparePairs are CMP-2's before and after reports, from saved reports of Docker boxes: a firewall closed (better, and
// DNS and UDP 53 only no longer found), a canary restored and the identity changed (unknown to pass), the demo's fix
// loop, a pair that got both better and worse, which still exits 6, and a check that no longer applies. The last two
// "before" reports, and the last "after", are built from public reports, and pass analysis.Load.
func comparePairs(t *testing.T) []struct {
	name, before, after string
	exit                int
} {
	t.Helper()
	load := func(path string) report.Doc {
		var d report.Doc
		b, err := os.ReadFile(path)
		if err == nil {
			err = json.Unmarshal(b, &d)
		}
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	vibe := load("../../demo/reports/vibe.json")
	// transplant gives d vibe's finding on id: its row, its findings entry and its count.
	transplant := func(d report.Doc, id string) report.Doc {
		d.Checks[slices.IndexFunc(d.Checks, func(c report.Check) bool { return c.ID == id })] =
			vibe.Checks[slices.IndexFunc(vibe.Checks, func(c report.Check) bool { return c.ID == id })]
		f := vibe.Findings[slices.IndexFunc(vibe.Findings, func(f report.Finding) bool { return f.ID == id })]
		d.Findings = append(d.Findings, f)
		d.Grade.Counts[f.Severity]++
		return d
	}
	dir := t.TempDir()
	save := func(name string, d report.Doc) string {
		path := filepath.Join(dir, name)
		b, err := json.Marshal(d)
		if err == nil {
			err = os.WriteFile(path, b, 0o600)
		}
		if err != nil {
			t.Fatal(err)
		}
		return path
	}
	mixed := save("mixed.json", transplant(load("../../demo/reports/hardened.json"), "PER-1"))
	sec2 := save("sec2-found.json", transplant(load("../../demo/reports/hardened.json"), "SEC-2"))
	hidden := load("../../demo/reports/hardened.json") // SEC-2 with no other process visible (KND-1)
	i := slices.IndexFunc(hidden.Checks, func(c report.Check) bool { return c.ID == "SEC-2" })
	hidden.Checks[i].Result, hidden.Checks[i].Proof, hidden.Checks[i].Reason = obs.ScopedOut, nil, "no other process is visible to the probe"
	scoped := save("sec2-scoped-out.json", hidden)
	for _, p := range []string{mixed, sec2, scoped} {
		if _, err := analysis.Load(p); err != nil {
			t.Fatalf("%s isn't a valid report: %v", p, err)
		}
	}
	return []struct {
		name, before, after string
		exit                int
	}{
		{"egress-closed", "../../test/reports/egress-open.json", "../../test/reports/egress-refused.json", 0},
		{"canary-restored", "../../test/reports/canary-down.json", "../../test/reports/egress-refused.json", 5},
		{"fix-loop", "../../demo/reports/vibe.json", "../../demo/reports/hardened.json", 5},
		{"better-and-worse", mixed, "../../demo/reports/regressed.json", 6},
		{"no-longer-applies", sec2, scoped, 0},
	}
}

// CMP-2: compare's text and JSON, byte for byte, in a UTF-8 locale. SANDPROBE_UPDATE_GOLDEN=1 rewrites the files.
func TestCompareGolden(t *testing.T) {
	t.Setenv("LC_ALL", "en_US.UTF-8")
	for _, tc := range comparePairs(t) {
		for _, format := range []string{"txt", "json"} {
			args := []string{"compare", tc.before, tc.after}
			if format == "json" {
				args = append(args, "-o", "json")
			}
			var out, errb bytes.Buffer
			if code := run(args, &out, &errb); code != tc.exit {
				t.Errorf("%s %s: exit %d, want %d: %s", tc.name, format, code, tc.exit, errb.String())
			}
			golden := filepath.Join("testdata", "compare", tc.name+"."+format)
			if os.Getenv("SANDPROBE_UPDATE_GOLDEN") == "1" {
				if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(golden, out.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("missing golden file %s: %v", golden, err)
			}
			if out.String() != string(want) {
				t.Errorf("%s %s: golden mismatch:\n--- got ---\n%s\n--- want ---\n%s", tc.name, format, out.String(), want)
			}
		}
	}
}

// CMP-2, UX-9: under C or POSIX, compare writes ASCII only (`*` bullets, `->` in the score line); in every locale,
// each line is within 80 display columns.
func TestCompareASCIIAndWidth(t *testing.T) {
	for _, locale := range []string{"C", "POSIX", "en_US.UTF-8"} {
		t.Setenv("LC_ALL", locale)
		ascii := locale != "en_US.UTF-8"
		for _, tc := range comparePairs(t) {
			var out, errb bytes.Buffer
			run([]string{"compare", tc.before, tc.after}, &out, &errb)
			s := out.String()
			for i, line := range strings.Split(s, "\n") {
				if cols := displayWidth(line); cols > 80 {
					t.Errorf("%s under %s: line %d is %d columns: %q", tc.name, locale, i+1, cols, line)
				}
			}
			if !ascii {
				continue
			}
			for _, r := range s {
				if r > 0x7f {
					t.Errorf("%s under %s: non-ASCII %q in:\n%s", tc.name, locale, r, s)
					break
				}
			}
			if !strings.Contains(s, "  * ") || !strings.Contains(s, " > ") || !strings.Contains(s, "Score: ") || !strings.Contains(s, " -> ") {
				t.Errorf("%s under %s: want * bullets, > and the -> arrow:\n%s", tc.name, locale, s)
			}
		}
	}
}

// CMP-2: a report with no score says which, and a check that ends scoped_out is listed apart, never as better.
func TestCompareNoScoreAndNoLongerApplies(t *testing.T) {
	t.Setenv("LC_ALL", "en_US.UTF-8")
	for _, tc := range []struct {
		before, after *analysis.Score
		want          string
	}{
		{nil, &analysis.Score{Score: 3, Of: 6}, "No score: the before report's run is invalid"},
		{&analysis.Score{Score: 3, Of: 6}, nil, "No score: the after report's run is invalid"},
		{nil, nil, "No score: both reports' runs are invalid"},
		{&analysis.Score{Score: 0, Of: 6}, &analysis.Score{Score: 4, Of: 5}, "Score: 0/6 → 4/5\n"},
	} {
		var out bytes.Buffer
		printComparison(opts{stdout: &out}, analysis.Comparison{GotBetter: []string{"SEC-3"}, NoLongerApplies: []string{"SEC-2"},
			ScoreBefore: tc.before, ScoreAfter: tc.after})
		s := out.String()
		if !strings.Contains(s, tc.want) || strings.Contains(s, "Score:") != (tc.before != nil && tc.after != nil) {
			t.Errorf("want %q in:\n%s", tc.want, s)
		}
		better, rest, _ := strings.Cut(s, "No longer applies (nothing left for it to check):\n")
		if !strings.Contains(better, "/etc/shadow?") || strings.Contains(better, "other programs' environment") ||
			!strings.HasPrefix(rest, "  ● Secrets › Can the agent open other programs' environment variables") {
			t.Errorf("SEC-2 must be listed only under No longer applies:\n%s", s)
		}
	}
}
