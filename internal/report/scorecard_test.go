package report

import (
	"encoding/json"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sandprobe/internal/catalog"
	"sandprobe/internal/obs"
	"sandprobe/internal/rundata"
)

// SCR-1: every catalog check is in exactly one category, with a label, and no category names a check that isn't one.
func TestCategoriesCoverCatalog(t *testing.T) {
	seen := map[string]string{}
	for _, cat := range Categories {
		for _, id := range cat.Checks {
			if _, ok := catalog.Get(id); !ok {
				t.Errorf("%s names %s, which isn't a catalog check", cat.Name, id)
			}
			if prev, dup := seen[id]; dup {
				t.Errorf("%s is in both %s and %s", id, prev, cat.Name)
			}
			seen[id] = cat.Name
			if cat.Label[id] == "" {
				t.Errorf("%s has no label in %s", id, cat.Name)
			}
			if !strings.HasSuffix(cat.Ask[id], "?") {
				t.Errorf("%s has no plain question in %s", id, cat.Name)
			}
		}
		if len(cat.Label) != len(cat.Checks) {
			t.Errorf("%s labels a check it doesn't hold", cat.Name)
		}
	}
	for _, id := range catalog.IDs() {
		if seen[id] == "" {
			t.Errorf("%s is in no category", id)
		}
	}
	if len(Categories) != 6 {
		t.Errorf("want six categories, got %d", len(Categories))
	}
}

// doc is a valid run where every check ended with result, then set overrides it per check.
func doc(result string, set map[string]Check) Doc {
	d := Doc{Grade: Grade{Valid: true}}
	for _, id := range catalog.IDs() {
		c := Check{ID: id, Result: result}
		if o, ok := set[id]; ok {
			c = o
			c.ID = id
		}
		d.Checks = append(d.Checks, c)
	}
	return d
}

func row(t *testing.T, c Card, name string) Row {
	t.Helper()
	for _, r := range c.Rows {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("no row %s", name)
	return Row{}
}

// SCR-2: green needs a tested check and nothing unknown or found above Info.
func TestScoreRules(t *testing.T) {
	if c := Score(doc(obs.Pass, nil)); c.Score != 6 || c.Of != 6 || !c.Valid {
		t.Fatalf("all proven: want 6/6, got %d/%d", c.Score, c.Of)
	}
	c := Score(doc(obs.Pass, map[string]Check{
		"PER-1":     {Result: obs.Finding, Severity: "low"},
		"EGR-4":     {Result: obs.Finding, Severity: "info"},
		"AMP-2":     {Result: obs.Unknown},
		"SEC-4":     {Result: "skipped"},
		"AMP-7":     {Result: "skipped"},
		"EGR-1":     {Result: obs.NotFound},
		"SEC-3":     {Result: obs.Finding}, // no severity recorded: never green
		"AMP-8.blk": {Result: obs.ScopedOut},
	}))
	if c.Score != 2 {
		t.Errorf("want 2/6, got %d", c.Score)
	}
	for name, want := range map[string]string{"Persistence": "Found: startup files", "Privilege": "Couldn't prove: root or capabilities",
		"Cloud access": "Not tested", "Secrets": "Found: credential files"} {
		if r := row(t, c, name); r.Green || r.Why != want {
			t.Errorf("%s: want red %q, got green=%v %q", name, want, r.Green, r.Why)
		}
	}
	if r := row(t, c, "Exfiltration"); !r.Green || r.NotProven != "not proven: DNS" {
		t.Errorf("Exfiltration: an Info finding stays green and DNS stays not proven, got %+v", r)
	}
	if r := row(t, c, "Containment"); !r.Green || r.NotProven != "" {
		t.Errorf("Containment: scoped out alongside passes is green, got %+v", r)
	}
	// missing checks are never green
	if r := row(t, Score(Doc{Grade: Grade{Valid: true}}), "Secrets"); r.Green || r.Why != "Not tested" {
		t.Errorf("no checks: want Not tested, got %+v", r)
	}
	// GRD-5: an invalid run has no score
	if c := Score(Doc{Grade: Grade{Valid: false}, Checks: doc(obs.Pass, nil).Checks}); c.Valid || c.Score != 0 || len(c.Rows) != 0 {
		t.Errorf("invalid: want no score, got %+v", c)
	}
}

// SCR-2: only known clean results count as clean, and an ID the grade calls unknown is unknown even without a row.
func TestScoreNeverCleanByDefault(t *testing.T) {
	for _, res := range []string{obs.Attempted, "", "passed", "PASS"} {
		if r := row(t, Score(doc(obs.Pass, map[string]Check{"AMP-5": {Result: res}})), "Containment"); r.Green {
			t.Errorf("result %q made Containment green", res)
		}
	}
	d := doc(obs.Pass, nil)
	var kept []Check
	for _, c := range d.Checks {
		if c.ID != "AMP-6" {
			kept = append(kept, c)
		}
	}
	d.Checks, d.Grade.Unknown = kept, []string{"AMP-6"}
	if r := row(t, Score(d), "Containment"); r.Green || r.Why != "Couldn't prove: vsock to the host" {
		t.Errorf("an unknown with no row: %+v", r)
	}
}

// SCR-2: across every saved report, six of six never shows where the letter isn't a complete A.
func TestSixOfSixIsAnA(t *testing.T) {
	var files []string
	for _, pat := range []string{"../../runs/*/*.json", "../../runs/*/*/*.json", "../../runs/*/*/*/*.json", "../../demo/reports/*.json"} {
		m, _ := filepath.Glob(pat)
		files = append(files, m...)
	}
	n, six := 0, 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var d Doc
		if json.Unmarshal(b, &d) != nil || d.Schema != Schema {
			continue // not a sandprobe/1 report: summaries, cleanup and provenance records
		}
		n++
		if c := Score(d); c.Score == c.Of {
			six++
			if d.Grade.Letter != "A" || !d.Grade.Complete {
				t.Errorf("%s: 6/6 with letter %q, complete %v", f, d.Grade.Letter, d.Grade.Complete)
			}
		}
	}
	least := 3 // the demo's three reports; the private provider runs add the rest where this tree has them
	if rundata.Present(t) {
		least = 18
	}
	if n < least || six == 0 {
		t.Fatalf("want the saved corpus with at least one 6/6 (the demo's hardened box), got %d reports, %d at 6/6", n, six)
	}
}

// SCR-3: reasons come from fixed labels only, and the page leads with the score, then the appendix.
func TestScorePage(t *testing.T) {
	hostile := "<b>sandprobe-fake</b>"
	d := doc(obs.Pass, map[string]Check{"SEC-3": {Result: obs.Finding, Severity: "high", Title: hostile, Evidence: hostile, Reason: hostile}})
	for _, r := range Score(d).Rows {
		if strings.Contains(r.Why+r.NotProven, "sandprobe-fake") {
			t.Fatalf("a box string reached a reason: %q", r.Why)
		}
	}
	page, err := HTML(d, "modern")
	if err != nil {
		t.Fatal(err)
	}
	p := string(page)
	s, w, a, l := strings.Index(p, "SANDBOX SCORE"), strings.Index(p, ">What we tested<"), strings.Index(p, ">Technical appendix<"),
		strings.Index(p, "LETTER GRADE")
	if s < 0 || w < s || a < w || l < a || !strings.Contains(p, "<b>5</b><span>/6</span>") {
		t.Errorf("want the score, what we tested, then the technical appendix with the letter: %d %d %d %d", s, w, a, l)
	}
	for _, cat := range Categories { // every test sits under its category, asked in plain words
		for _, id := range cat.Checks {
			if !strings.Contains(p, `id="`+id+`"><td class="sev">`) || !strings.Contains(p, template.HTMLEscapeString(cat.Ask[id])) {
				t.Errorf("%s isn't asked in plain words under %s", id, cat.Name)
			}
		}
	}
	// failures above the fold, passes folded away, and how many tests ran
	sec := p[strings.Index(p, "Can it read keys and tokens?</span>"):]
	sec = sec[:strings.Index(sec, "</section>")]
	fail, fold, pass := strings.Index(sec, `id="SEC-3"`), strings.Index(sec, `<details class="more">`), strings.Index(sec, `id="SEC-1"`)
	if fail < 0 || fold < fail || pass < fold || !strings.Contains(sec, "4/4 tests run") || !strings.Contains(sec, "Show 3 passed") {
		t.Errorf("Secrets: want the failure, then the fold, then the passes, and 4/4 run: %d %d %d", fail, fold, pass)
	}
	d.Grade.Valid = false
	page, _ = HTML(d, "modern")
	if !strings.Contains(string(page), "INVALID RUN: NO SCORE") || strings.Contains(string(page), "SANDBOX SCORE") {
		t.Error("an invalid run's page must show no score")
	}
}

// SCR-2 and HCN-5: a run without a canary says "not tested" for Exfiltration, from the host's own flag, and stays red;
// the same unknowns without that flag, or with an unknown the canary doesn't explain, read "couldn't prove".
func TestScoreNoCanary(t *testing.T) {
	unknowns := map[string]Check{}
	for _, id := range []string{"EGR-1", "EGR-2", "EGR-3", "EGR-4", "EGR-5.22", "EGR-5.80", "EGR-5.8080", "EGR-5.53u"} {
		unknowns[id] = Check{Result: obs.Unknown}
	}
	d := doc(obs.Pass, unknowns)
	d.Run.NoCanary = true
	if r := row(t, Score(d), "Exfiltration"); r.Green || r.Why != "Not tested: run without a canary" {
		t.Errorf("no canary: %+v", r)
	}
	d.Run.NoCanary = false
	if r := row(t, Score(d), "Exfiltration"); r.Green || !strings.HasPrefix(r.Why, "Couldn't prove") {
		t.Errorf("a box can't claim no canary: %+v", r)
	}
	unknowns["EGR-6"] = Check{Result: obs.Unknown}
	d = doc(obs.Pass, unknowns)
	d.Run.NoCanary = true
	if r := row(t, Score(d), "Exfiltration"); r.Green || !strings.HasPrefix(r.Why, "Couldn't prove") {
		t.Errorf("an unknown the canary doesn't explain: %+v", r)
	}
}
