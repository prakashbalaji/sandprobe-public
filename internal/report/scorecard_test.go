package report

import (
	"encoding/json"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sandprobe/internal/catalog"
	"sandprobe/internal/host"
	"sandprobe/internal/obs"
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

// SCR-2: across every saved report, a full score never shows where the letter isn't a complete A. Each is a local
// Docker run, where Cloud access is tested, so each stays out of six with no category left out.
func TestSixOfSixIsAnA(t *testing.T) {
	var files []string
	for _, pat := range []string{"../../demo/reports/*.json", "../../test/reports/*.json"} {
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
		if json.Unmarshal(b, &d) != nil || d.Schema != SchemaFor(d.Manifest) {
			continue // not a sandprobe report: summaries, cleanup and provenance records
		}
		n++
		if c := Score(d); c.Of != 6 || len(c.NotCounted()) != 0 {
			t.Errorf("%s: a Docker run scored out of %d, leaving out %q", f, c.Of, c.NotCounted())
		}
		if c := Score(d); c.Score == c.Of {
			six++
			if d.Grade.Letter != "A" || !d.Grade.Complete {
				t.Errorf("%s: 6/6 with letter %q, complete %v", f, d.Grade.Letter, d.Grade.Complete)
			}
		}
	}
	least := 6 // the demo's three reports and test/reports' three
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
	doc := p[strings.Index(p, `<main class="doc">`):] // the contents rail names the sections too
	h, s, w, a := strings.Index(doc, `id="summary"`), strings.Index(doc, "Sandbox score"), strings.Index(doc, ">What to fix<"),
		strings.Index(doc, ">Technical appendix<")
	if h < 0 || s < h || w < s || a < w || !strings.Contains(p, "<b>5</b><span>/6</span>") {
		t.Errorf("want the header, the score, what to fix, then the technical appendix: %d %d %d %d", h, s, w, a)
	}
	for _, cat := range Categories { // every test is asked in plain words, beside its category
		for _, id := range cat.Checks {
			if r := rowOf(p, id); !strings.Contains(r, template.HTMLEscapeString(cat.Ask[id])) || !strings.Contains(r, `<span class="ctag">`+cat.Name+`</span>`) {
				t.Errorf("%s isn't asked in plain words beside %s", id, cat.Name)
			}
		}
	}
	// the failure in its severity above the fold, the passes folded away, and how many of a row's tests ran
	high, fold, pass := strings.Index(p, `id="sev-high"`), strings.Index(p, `<details class="more">`), strings.Index(p, `id="SEC-1"`)
	if high < 0 || fold < high || !strings.Contains(p[high:fold], `id="SEC-3"`) || pass < fold || !strings.Contains(p, "4/4 tests run") ||
		!strings.Contains(p, "Show 27 passed") {
		t.Errorf("want SEC-3 under High, then the fold with the passes, and 4/4 run: %d %d %d", high, fold, pass)
	}
	d.Grade.Valid = false
	page, _ = HTML(d, "modern")
	if !strings.Contains(string(page), "Invalid run: no score") || strings.Contains(string(page), "Sandbox score") {
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

// SCR-2: a green category with no conclusive check (Conclusive == 0) carries GreenNotProven, still counts toward the
// score, and reads "GREEN · NOT PROVEN", dashed, on the page; a green row with any conclusive check, an Info finding
// included, stays plain GREEN; a supplied flag that contradicts coverage, sits on a red row or comes without coverage
// is refused, and a dropped one is still valid.
func TestGreenNotProven(t *testing.T) {
	read := func(path string) Doc {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var d Doc
		if err := json.Unmarshal(b, &d); err != nil {
			t.Fatal(err)
		}
		return d
	}
	vibe := read("../../demo/reports/vibe.json")
	vc := Score(vibe)
	if vc.Score != 1 || vc.Of != 6 {
		t.Fatalf("vibe score: want 1/6, got %d/%d", vc.Score, vc.Of)
	}
	cloud := row(t, vc, "Cloud access")
	if !cloud.Green || !cloud.GreenNotProven || cloud.Coverage == nil || cloud.Coverage.Conclusive != 0 || cloud.Coverage.Total != 2 {
		t.Fatalf("vibe Cloud access: want green and not proven at 0/2 conclusive, got %+v (coverage %+v)", cloud, cloud.Coverage)
	}
	for _, r := range vc.Rows {
		if r.Name != "Cloud access" && r.GreenNotProven {
			t.Errorf("vibe %s: a red row carries the flag", r.Name)
		}
	}
	if b, _ := json.Marshal(vc); strings.Count(string(b), `"green_not_proven":true`) != 1 {
		t.Errorf("the card's JSON: %s", b)
	}
	for _, theme := range []string{"graphite", "mission"} {
		page, err := HTML(vibe, theme)
		if err != nil {
			t.Fatal(err)
		}
		p := string(page)
		if strings.Count(p, `<li class="cat green gnp"`) != 1 || strings.Count(p, `<span class="verdict">GREEN · NOT PROVEN</span>`) != 1 ||
			!strings.Contains(p, ".cats .green.gnp .dot { background: none; border: 1.5px dashed var(--green); }") ||
			!strings.Contains(p, ".cat.green.gnp .verdict { border-style: dashed; }") {
			t.Errorf("%s: the page has no dashed GREEN · NOT PROVEN badge for Cloud access", theme)
		}
	}
	page, err := HTML(read("../../demo/reports/hardened.json"), "graphite")
	if err != nil {
		t.Fatal(err)
	}
	if p := string(page); strings.Count(p, `<li class="cat green"`) != 5 || strings.Count(p, `<li class="cat green gnp"`) != 1 ||
		strings.Count(p, `<span class="verdict">GREEN</span>`) != 5 {
		t.Error("hardened: want five proven GREEN rows and Cloud access not proven")
	}

	// Every row green on not_found alone: all six flagged, and all six still counted.
	if c := Score(doc(obs.NotFound, nil)); c.Score != 6 || c.Of != 6 {
		t.Errorf("not proven left the score: %d/%d", c.Score, c.Of)
	} else {
		for _, r := range c.Rows {
			if !r.Green || !r.GreenNotProven {
				t.Errorf("all not_found: %s %+v", r.Name, r)
			}
		}
	}
	scoped := map[string]Check{}
	for _, id := range Categories[5].Checks {
		scoped[id] = Check{Result: obs.ScopedOut}
	}
	if r := row(t, Score(doc(obs.Pass, scoped)), "Persistence"); !r.Green || !r.GreenNotProven || r.NotProven != "" {
		t.Errorf("only scoped_out: want green and not proven, got %+v", r)
	}
	// A pass beside a not_found is conclusive: plain GREEN with its "not proven" line.
	if r := row(t, Score(doc(obs.Pass, map[string]Check{"EGR-1": {Result: obs.NotFound}})), "Exfiltration"); !r.Green || r.GreenNotProven || r.NotProven != "not proven: DNS" {
		t.Errorf("a pass beside a not_found: want plain green, got %+v", r)
	}
	// An Info finding is a completed observation (SCR-5): plain GREEN with its "not proven" line, never the label.
	info := map[string]Check{}
	for _, id := range Categories[0].Checks {
		info[id] = Check{Result: obs.NotFound}
	}
	info["SEC-3"] = Check{Result: obs.Finding, Severity: "info"}
	if r := row(t, Score(doc(obs.Pass, info)), "Secrets"); !r.Green || r.GreenNotProven || r.Coverage.Conclusive != 1 || r.NotProven == "" {
		t.Errorf("an Info finding beside not_found: want plain green, got %+v (coverage %+v)", r, r.Coverage)
	}

	forged := Score(doc(obs.Pass, nil))
	forged.Rows[0].GreenNotProven = true
	if validCardCoverage(forged) {
		t.Error("accepted the flag on a category with conclusive passes")
	}
	dropped := Score(vibe)
	dropped.Rows[4].GreenNotProven = false
	if !validCardCoverage(dropped) {
		t.Error("refused coverage without the optional display flag")
	}
	exposure := func(c Card) WorkloadExposure {
		return WorkloadExposure{Schema: "sandprobe.workload-exposure/1", InputVerification: "proof_recomputation_unauthenticated_input", Card: c}
	}
	if !validWorkloadExposure(exposure(Score(vibe))) {
		t.Fatal("refused an honest not-proven workload exposure")
	}
	red := Score(vibe)
	red.Rows[0].GreenNotProven = true // Secrets is red in vibe.json
	if validWorkloadExposure(exposure(red)) {
		t.Error("accepted the flag on a red row")
	}
	bare := Score(vibe)
	bare.Coverage = nil
	for i := range bare.Rows {
		bare.Rows[i].Coverage = nil
	}
	if validWorkloadExposure(exposure(bare)) {
		t.Error("accepted the flag on a card without coverage")
	}
	bare.Rows[4].GreenNotProven = false
	if !validWorkloadExposure(exposure(bare)) {
		t.Error("refused a historical card without coverage or the flag")
	}
}

// SCR-2 and AGENTS.md rule 1: the label only ever weakens a green. An unknown keeps a row red; not applicable, opt-in
// and plain not-tested rows and an invalid run never carry the flag or the label.
func TestGreenNotProvenNeverStrengthens(t *testing.T) {
	flagged := func(c Card) bool {
		for _, r := range c.Rows {
			if r.GreenNotProven {
				return true
			}
		}
		return false
	}
	for name, d := range map[string]Doc{
		"AMP-7 unknown": doc(obs.Pass, map[string]Check{"SEC-4": {Result: obs.NotFound}, "AMP-7": {Result: obs.Unknown}}),
		"AMP-7 in the grade's unknown": func() Doc {
			d := doc(obs.Pass, map[string]Check{"SEC-4": {Result: obs.NotFound}, "AMP-7": {Result: obs.NotFound}})
			d.Grade.Unknown = []string{"AMP-7"}
			return d
		}(),
	} {
		if r := row(t, Score(d), "Cloud access"); r.Green || r.GreenNotProven || !strings.HasPrefix(r.Why, "Couldn't prove") {
			t.Errorf("%s: a 0-conclusive row with an unknown: want red, got %+v", name, r)
		}
	}
	for provider, excluded := range natives {
		d := replanned(t, provider, host.Options{Mode: "exec", Excluded: excluded, ExcludedKind: obs.SkipProviderTerms})
		c := Score(d)
		if r := row(t, c, "Cloud access"); !r.NotApplicable || r.Green || r.GreenNotProven {
			t.Errorf("%s: not applicable Cloud access %+v", provider, r)
		}
		page, err := HTML(d, "graphite")
		if err != nil {
			t.Fatal(err)
		}
		if p := string(page); flagged(c) || strings.Contains(p, "gnp\"") || strings.Contains(p, "NOT PROVEN</span>") {
			t.Errorf("%s: a not-proven label with no 0-conclusive green row", provider)
		}
	}
	for provider, excluded := range map[string]map[string]string{"exec": host.ExecExclusions(), "kubernetes": {
		"SEC-4": "recipe", "EGR-3": "recipe", "AMP-6": "recipe", "AMP-7": "recipe"}} {
		c := Score(replanned(t, provider, host.Options{Mode: "exec", Excluded: excluded, ExcludedKind: obs.SkipOptIn}))
		if r := row(t, c, "Cloud access"); r.Green || r.GreenNotProven || !strings.HasPrefix(r.Why, "Not tested: opt in") || flagged(c) {
			t.Errorf("%s: opt-in Cloud access %+v", provider, r)
		}
	}
	if c := Score(doc(obs.Skipped, nil)); flagged(c) || c.Score != 0 {
		t.Errorf("nothing tested: %d/%d, flagged %v", c.Score, c.Of, flagged(c))
	}
	b, err := os.ReadFile("../../demo/reports/vibe.json")
	if err != nil {
		t.Fatal(err)
	}
	var invalid Doc
	if err := json.Unmarshal(b, &invalid); err != nil {
		t.Fatal(err)
	}
	invalid.Grade.Valid, invalid.Grade.Invalid = false, "an edited report"
	c := Score(invalid)
	if c.Valid || len(c.Rows) != 0 {
		t.Errorf("an invalid run has rows: %+v", c)
	}
	page, err := HTML(invalid, "graphite")
	if err != nil {
		t.Fatal(err)
	}
	if j, _ := json.Marshal(c); strings.Contains(string(j), "green_not_proven") || strings.Contains(string(page), "NOT PROVEN</span>") {
		t.Error("an invalid run carries the not-proven label")
	}
}
