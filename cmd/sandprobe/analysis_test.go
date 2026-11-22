package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sandprobe/internal/report"
	"strings"
	"testing"
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
