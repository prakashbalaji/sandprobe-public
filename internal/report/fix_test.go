package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"sandprobe/internal/catalog"
	"sandprobe/internal/grade"
	"sandprobe/internal/host"
	"sandprobe/internal/obs"
)

// pages is every report SCR-3's page must hold up on: the saved reports, the synthetic run with hostile box text, an
// invalid run, a not-applicable run, and run exec's opt-in run with and without a canary.
func pages(t *testing.T) map[string]Doc {
	t.Helper()
	invalid := run()
	invalid.Report = grade.Report{Invalid: "a duplicate check ID"}
	docs := map[string]Doc{"synthetic": Build(run(), meta()), "invalid": Build(invalid, meta()),
		"not applicable": replanned(t, "sprites", host.Options{Mode: "exec", Excluded: host.SpritesExclusions(), ExcludedKind: obs.SkipProviderTerms}),
		"opt-in":         replanned(t, "exec", host.Options{Mode: "exec", Excluded: host.ExecExclusions(), ExcludedKind: obs.SkipOptIn}),
		"no canary":      replanned(t, "exec", host.Options{Mode: "exec", Excluded: host.ExecExclusions(), ExcludedKind: obs.SkipOptIn, NoCanary: true})}
	for _, pat := range []string{"../../demo/reports/*.json", "../../test/reports/*.json"} {
		m, _ := filepath.Glob(pat)
		for _, f := range m {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			var d Doc
			if json.Unmarshal(b, &d) == nil && d.Schema != "" {
				docs[f] = d
			}
		}
	}
	if len(docs) < 11 {
		t.Fatalf("want the five synthetic runs and the six saved reports, got %d", len(docs))
	}
	return docs
}

// between is the page from the first from to the next to after it, or "".
func between(page, from, to string) string {
	i := strings.Index(page, from)
	if i < 0 {
		return ""
	}
	j := strings.Index(page[i:], to)
	if j < 0 {
		return ""
	}
	return page[i : i+j]
}

// groupOf is one group of What to fix: a severity, "unknown", or "rest" for the fold.
func groupOf(page, key string) string {
	return between(page, `<section class="grp" id="sev-`+key+`"`, "</section>")
}

func pageOf(t *testing.T, d Doc, theme string) string {
	t.Helper()
	b, err := HTML(d, theme)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

var (
	hrefRE = regexp.MustCompile(`href="#([^"]*)"`)
	idRE   = regexp.MustCompile(`\sid="([^"]*)"`)
)

// SCR-3: the header, then the score with its strip and the six rows, then What to fix, then the appendix.
func TestPageOrder(t *testing.T) {
	b, err := os.ReadFile("../../demo/reports/vibe.json")
	if err != nil {
		t.Fatal(err)
	}
	var d Doc
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	p := pageOf(t, d, "graphite")
	head := between(p, `<header class="head"`, "</header>")
	for _, want := range []string{`<h1>sandprobe-demo/vibe</h1>`, `<span class="tag">docker</span>`,
		`<span class="sevtag">critical</span>The agent can open a credential and send data out of the box, so a hijacked agent could steal it.`,
		"<dt>Ran</dt>", `<dt>Probe</dt><dd class="mono">0.1.0</dd>`, "<dd>Host-shipped, not attested</dd>"} {
		if !strings.Contains(head, want) {
			t.Errorf("the header doesn't hold %s", want)
		}
	}
	if strings.Contains(head, "Mode") || strings.Contains(head, ">"+d.Run.Mode+"<") {
		t.Error("the header shows run.mode, the probe's launch path, as a fact of the run")
	}
	last := -1
	for _, mark := range []string{`<header class="head"`, `<section class="score"`, `<ul class="stats"`, `<ol class="cats">`, `<section class="sec" id="fix">`,
		`id="sev-critical"`, `id="sev-high"`, `id="sev-medium"`, `id="sev-low"`, `id="sev-rest"`, ">Technical appendix<", `id="map"`, `id="ran"`, `id="covers"`} {
		i := strings.Index(p, mark)
		if i <= last {
			t.Errorf("%s is out of order (%d after %d)", mark, i, last)
		}
		last = i
	}
	crit := groupOf(p, "critical") // the chain's sentence leads its severity, with its fix and a link to each check it joins
	if strings.Index(crit, `<li class="row `) != strings.Index(crit, `<li class="row red" id="CHN-1">`) || !strings.Contains(crit, "<b>Fix</b>") {
		t.Error("CHN-1 doesn't lead Critical with its fix")
	}
	for _, f := range d.Findings {
		if f.ID == "CHN-1" {
			for _, part := range f.Checks {
				if !strings.Contains(rowOf(p, "CHN-1"), `<a href="#`+part+`">`+part+`</a>`) {
					t.Errorf("CHN-1 doesn't link %s", part)
				}
			}
		}
	}
	for i, cat := range Categories { // each row says how many of its tests ran, and links to each
		card := between(p, fmt.Sprintf(`id="cat-%d"`, i+1), "</li>")
		if !strings.Contains(card, fmt.Sprintf("/%d tests run</span>", len(cat.Checks))) {
			t.Errorf("%s doesn't say how many of its tests ran", cat.Name)
		}
		for _, id := range cat.Checks {
			if !strings.Contains(card, `href="#`+id+`"`) {
				t.Errorf("%s doesn't link %s", cat.Name, id)
			}
		}
	}
	if groupOf(p, "unknown") != "" {
		t.Error("a complete run shows an Unknown group")
	}
}

// SCR-3: every test appears exactly once, on every report's page, fresh or re-rendered, in both palettes, and every
// link on the page lands on something there.
func TestEveryTestOnce(t *testing.T) {
	for name, d := range pages(t) {
		for _, theme := range []string{"graphite", "mission"} {
			for _, render := range []func(Doc, string) ([]byte, error){HTML, SavedHTML} {
				b, err := render(d, theme)
				if err != nil {
					t.Fatal(name, err)
				}
				p := string(b)
				ids := map[string]bool{}
				for _, m := range idRE.FindAllStringSubmatch(p, -1) {
					ids[m[1]] = true
				}
				for _, m := range hrefRE.FindAllStringSubmatch(p, -1) {
					if !ids[m[1]] {
						t.Errorf("%s, %s: #%s lands nowhere", name, theme, m[1])
					}
				}
				if !d.Grade.Valid {
					if strings.Contains(p, `<li class="row `) {
						t.Errorf("%s, %s: an invalid run lists tests", name, theme)
					}
					continue
				}
				for _, id := range catalog.IDs() {
					if n := strings.Count(p, `id="`+id+`"`); n != 1 || rowOf(p, id) == "" {
						t.Errorf("%s, %s: %s has %d rows", name, theme, id, n)
					}
				}
			}
		}
	}
}

// SCR-3: a failure with no known severity (only an edited report has one) still shows, once, and is counted.
func TestEveryTestOnceUnrated(t *testing.T) {
	p := pageOf(t, doc(obs.Pass, map[string]Check{"SEC-3": {Result: obs.Finding}}), "graphite")
	if !strings.Contains(groupOf(p, "unrated"), `id="SEC-3"`) || strings.Count(p, `id="SEC-3"`) != 1 ||
		!strings.Contains(p, `<b class="red">1</b><span>unrated failing</span>`) {
		t.Error("a failure with no known severity is dropped, or not counted")
	}
}

// SCR-3: every count on the page counts the rows it shows, and equals the grade's own counts.
func TestCountsComeFromRows(t *testing.T) {
	for name, d := range pages(t) {
		if !d.Grade.Valid {
			continue
		}
		p := pageOf(t, d, "graphite")
		strip, rail := between(p, `<ul class="stats"`, "</ul>"), between(p, `<nav class="toc"`, "</nav>")
		failing := 0
		for _, g := range failGroups {
			sev, title := g[0], g[1]
			n := strings.Count(groupOf(p, sev), `<li class="row `)
			failing += n
			if n != d.Grade.Counts[sev] {
				t.Errorf("%s: %d %s rows, but the grade counts %d", name, n, sev, d.Grade.Counts[sev])
			}
			if n == 0 {
				if strings.Contains(strip, sev+" failing") || strings.Contains(rail, `href="#sev-`+sev+`"`) {
					t.Errorf("%s: %s is counted with no row", name, sev)
				}
				continue
			}
			if !strings.Contains(strip, fmt.Sprintf(`<b class="red">%d</b><span>%s failing</span>`, n, sev)) ||
				!strings.Contains(groupOf(p, sev), fmt.Sprintf(`<span class="q">%d failing</span>`, n)) ||
				!strings.Contains(rail, fmt.Sprintf(`%s<span class="spacer"></span><span class="n">%d</span>`, title, n)) {
				t.Errorf("%s: the strip, the heading or the rail doesn't count %d %s", name, n, sev)
			}
		}
		if failing == 0 && !strings.Contains(strip, `<b class="">0</b><span>failing</span>`) {
			t.Errorf("%s: no failure, and the strip doesn't say 0", name)
		}
		unknown, dashed := strings.Count(groupOf(p, "unknown"), `<li class="row `), "unk"
		if unknown == 0 {
			dashed = ""
		}
		if unknown != len(d.Grade.Unknown) || !strings.Contains(strip, fmt.Sprintf(`<b class="%s">%d</b><span>unknown</span>`, dashed, unknown)) {
			t.Errorf("%s: %d unknown rows, the grade lists %d", name, unknown, len(d.Grade.Unknown))
		}
		rest, passed := groupOf(p, "rest"), 0
		for _, ck := range d.Checks {
			if ck.Result == obs.Pass || ck.Result == obs.Absent {
				passed++
			}
		}
		n := strings.Count(rest, `<li class="row `)
		if strings.Count(rest, `<li class="row green"`) != passed || !strings.Contains(strip, fmt.Sprintf(`>%d</b><span>passed</span>`, passed)) ||
			!strings.Contains(rest, fmt.Sprintf(`<span class="q">%d tests</span>`, n)) ||
			!strings.Contains(rail, fmt.Sprintf(`Passed, or not proven<span class="spacer"></span><span class="n">%d</span>`, n)) {
			t.Errorf("%s: the fold's %d rows or its %d passes aren't what's counted", name, n, passed)
		}
	}
}

// SCR-3, UX-8 and rule 1: what couldn't be told is never shown as a pass, and a not-proven test never as a refusal.
func TestUnknownIsNeverAPass(t *testing.T) {
	p := pageOf(t, Build(run(), meta()), "graphite") // AMP-1 unknown, SEC-4 not found, EGR-2 a medium finding
	if !strings.Contains(p, `<p class="status">Incomplete: 1 check unknown</p>`) {
		t.Error("an incomplete run with a finding doesn't say it's incomplete beside the score")
	}
	fold := strings.Index(p, `<details class="more">`)
	if r := rowOf(p, "AMP-1"); !strings.Contains(r, `<li class="row amber"`) || !strings.Contains(r, `<span class="key">Unknown</span>`) ||
		!strings.Contains(groupOf(p, "unknown"), `id="AMP-1"`) || strings.Index(p, `id="AMP-1"`) > fold {
		t.Error("AMP-1 isn't a dashed unknown, unfolded in its own group")
	}
	if r := rowOf(p, "SEC-4"); !strings.Contains(r, `<li class="row grey"`) || !strings.Contains(r, `<span class="key">No finding</span>`) ||
		!strings.Contains(r, "doesn&#39;t prove") || strings.Index(p, `id="SEC-4"`) < fold {
		t.Error("SEC-4 isn't folded as a no-finding that proves nothing")
	}
	if !strings.Contains(p, `<a class="t amber" href="#AMP-1"`) || !strings.Contains(p, `<a class="t grey" href="#SEC-4"`) {
		t.Error("a row's links don't keep the unknown and the not-proven apart from a pass")
	}
	for _, rule := range []string{`.row.amber .key { color: var(--unk); background: none; border: 1px dashed var(--unk-edge); }`,
		`a.t.amber { color: var(--unk); border: 1px dashed var(--unk-edge); }`, `.stats b.unk { padding: 0 5px 1px; border: 1px dashed var(--unk-edge);`} {
		if !strings.Contains(p, rule) {
			t.Errorf("an unknown isn't dashed: no %s", rule)
		}
	}
	d := doc(obs.Pass, map[string]Check{"AMP-2": {Result: obs.Unknown}}) // incomplete, with nothing found
	d.Grade = Grade{Valid: true, Letter: "C", Unknown: []string{"AMP-2"}}
	p = pageOf(t, d, "graphite")
	if !strings.Contains(p, `<p class="status">Incomplete: 1 check unknown</p>`) || !strings.Contains(p, `<b class="unk">1</b><span>unknown</span>`) ||
		!strings.Contains(p, `.status { display: table; margin: 10px 0 0; padding: 5px 12px 6px; border: 1px dashed var(--unk-edge);`) {
		t.Error("an incomplete run with nothing found isn't said, dashed, beside the score")
	}
}

var (
	gradeRE = regexp.MustCompile(`(?i)\b(grade|letter)\b`)
	codeRE  = regexp.MustCompile(`(?s)<script nonce="[^"]*">.*?</script>`)
)

// SCR-3 and UX-8: the page shows no letter grade, its title included, for a valid, an incomplete and an invalid run,
// fresh or re-rendered, in both palettes. The title carries the score, beside which the page says an incomplete run is
// incomplete, and an invalid run says plainly that it is invalid and has no score. The JSON keeps the grade (OUT-1).
func TestNoLetterGrade(t *testing.T) {
	load := func(f string) Doc {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var d Doc
		if err := json.Unmarshal(b, &d); err != nil {
			t.Fatal(err)
		}
		return d
	}
	invalid := run()
	invalid.Report = grade.Report{Invalid: "a duplicate check ID"}
	for name, tc := range map[string]struct {
		d           Doc
		title, says string
	}{
		"valid":      {load("../../demo/reports/vibe.json"), "Sandprobe · docker · score 1/6", "1 of 6 categories is green"},
		"incomplete": {load("../../test/reports/canary-down.json"), "Sandprobe · docker-fixture · score 2/6", `<p class="status">Incomplete: 6 checks unknown</p>`},
		"invalid": {Build(invalid, meta()), "Sandprobe · sprites · invalid, no score",
			`<p class="kicker"><em>Invalid run: no score</em></p>
  <p class="banner unk">Why this run is invalid: a duplicate check ID</p>`},
	} {
		if tc.d.Grade.Letter == "" && tc.d.Grade.Valid {
			t.Fatalf("%s: the report has no letter to hide", name)
		}
		for _, theme := range []string{"graphite", "mission"} {
			for _, render := range []func(Doc, string) ([]byte, error){HTML, SavedHTML} {
				b, err := render(tc.d, theme)
				if err != nil {
					t.Fatal(err)
				}
				p := string(b)
				if !strings.Contains(p, "<title>"+tc.title+"</title>") || !strings.Contains(p, tc.says) {
					t.Errorf("%s, %s: want the title %q and %q beside the score", name, theme, tc.title, tc.says)
				}
				text := codeRE.ReplaceAllString(styleRE.ReplaceAllString(dataRE.ReplaceAllString(p, ""), ""), "") // what a reader sees
				if m := gradeRE.FindString(text); m != "" || tc.d.Grade.Letter != "" && strings.Contains(text, ">"+tc.d.Grade.Letter+"<") {
					t.Errorf("%s, %s: the page shows a letter grade (%q)", name, theme, m)
				}
				if !strings.Contains(dataRE.FindString(p), `"letter":`) {
					t.Errorf("%s, %s: the JSON lost its grade", name, theme)
				}
			}
		}
	}
}

// SCR-3: the header's facts come from the report as text, except the attestation, which is fixed (SBX-10).
func TestHeaderFacts(t *testing.T) {
	m := meta()
	m.Version = evil
	d := Build(run(), m)
	d.Probe.Attested = true // an edited report can't make the page claim an attestation
	p := pageOf(t, d, "graphite")
	head := between(p, `<header class="head"`, "</header>")
	if strings.Contains(head, "<script>alert") || !strings.Contains(head, `<dt>Probe</dt><dd class="mono">&lt;/script&gt;&lt;script&gt;alert(1)`) {
		t.Error("the probe's version isn't escaped as text")
	}
	if !strings.Contains(head, "<dd>Host-shipped, not attested</dd>") || strings.Count(p, "ttested</dd>") != 1 {
		t.Error("the attestation line isn't the fixed one")
	}
	if !strings.Contains(head, `<p class="lede">`+template.HTMLEscapeString(d.Lead)+"</p>") || strings.Contains(head, "sevtag") {
		t.Error("without a chain, the header doesn't lead with the lead sentence")
	}
	if strings.Contains(head, "Mode") {
		t.Error("the header shows run.mode")
	}
	m.Version = ""
	if head := between(pageOf(t, Build(run(), m), "graphite"), `<header class="head"`, "</header>"); strings.Contains(head, "<dt>Probe</dt>") {
		t.Error("an empty version is shown")
	}
}

// SCR-3 and GRD-5: an invalid run's page counts nothing, since "0 failing, 0 passed" would read as clean.
func TestInvalidHasNoCounts(t *testing.T) {
	r := run()
	r.Report = grade.Report{Invalid: "a duplicate check ID"}
	p := pageOf(t, Build(r, meta()), "graphite")
	for _, bad := range []string{`<ul class="stats"`, `<section class="grp"`, `id="fix"`, `<span class="spacer"></span><span class="n">`, `<li class="row `, `<ol class="cats">`, "Sandbox score"} {
		if strings.Contains(p, bad) {
			t.Errorf("an invalid run's page holds %s", bad)
		}
	}
	if !strings.Contains(between(p, `<header class="head"`, "</header>"), "This run is invalid, so it says nothing about the box: a duplicate check ID") {
		t.Error("an invalid run's header doesn't say so")
	}
}

// SCR-6: scope discovery must not inflate executed-access coverage in either theme.
func TestHTMLExecutedCountsExcludeScopeOnlyResults(t *testing.T) {
	d := doc(obs.Pass, map[string]Check{
		"AMP-4":     {Result: obs.Unknown},
		"AMP-5":     {Result: obs.NotFound},
		"AMP-6":     {Result: obs.Skipped},
		"AMP-8.sys": {Result: obs.ScopedOut},
	})
	var kept []Check
	for _, c := range d.Checks {
		if c.ID != "AMP-8.blk" {
			kept = append(kept, c)
		}
	}
	d.Checks = kept
	before := Score(d)
	for _, theme := range []string{"graphite", "paper"} {
		b, err := HTML(d, theme)
		if err != nil {
			t.Fatal(err)
		}
		card := between(string(b), `id="cat-3"`, "</li>")
		if !strings.Contains(card, "2/5 tests run</span>") {
			t.Errorf("%s: unknown and not-found should count; skipped, scoped-out and missing must not: %s", theme, card)
		}
	}
	if after := Score(d); after.Score != before.Score || after.Of != before.Of {
		t.Fatal("rendering changed the score")
	}
}
