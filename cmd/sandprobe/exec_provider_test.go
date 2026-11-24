package main

import (
	"bytes"
	"encoding/json"
	"html"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"sandprobe/internal/canary"
	"sandprobe/internal/catalog"
	"sandprobe/internal/host"
	"sandprobe/internal/obs"
	"sandprobe/internal/report"
)

// declaredSaved is a saved run exec report whose operator declared name with -provider (PRV-17): planned through
// host.Plan, so its kinds are exactly what the host writes.
func declaredSaved(t *testing.T, name string) (string, report.Doc) {
	t.Helper()
	path := skipSaved(t, "exec", host.Options{Excluded: execExclusions(name, nil), ExcludedKind: obs.SkipOptIn, DeclaredProvider: name})
	b, _ := os.ReadFile(path)
	var d report.Doc
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	if d.Manifest.DeclaredProvider != name || d.Schema != report.SchemaDeclaredProvider {
		t.Fatalf("the declared report: %q, %s", d.Manifest.DeclaredProvider, d.Schema)
	}
	return path, d
}

// writeDoc saves d as a report file.
func writeDoc(t *testing.T, d report.Doc) string {
	t.Helper()
	b, _ := json.Marshal(d)
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// PRV-17: -provider takes exactly a key of this binary's PRV-row table, on run exec and plan exec only. Anything else is
// a usage error before the plan exists, which lists the valid names and never echoes the value given.
func TestExecProviderParse(t *testing.T) {
	keys := slices.Sorted(func(yield func(string) bool) {
		for k := range host.TermsExclusions {
			if !yield(k) {
				return
			}
		}
	})
	if !slices.Equal(host.DeclarableProviders(), keys) {
		t.Fatalf("DeclarableProviders %v, the table %v", host.DeclarableProviders(), keys)
	}
	for _, name := range keys {
		var out, errs bytes.Buffer
		if code := run([]string{"plan", "exec", "-provider", name, "--", "sh"}, &out, &errs); code != exitGraded {
			t.Errorf("%s: exit %d, %s", name, code, errs.String())
		}
	}
	list := strings.Join(keys, ", ")
	for _, value := range []string{"", "exec", "docker", "aws-nitro", "kubernetes", "Modal", " modal", "modal ", "modal,sprites", "sk-live-SECRETLOOKING"} {
		var out, errs bytes.Buffer
		code := run([]string{"plan", "exec", "-provider", value, "--", "sh"}, &out, &errs)
		if code != exitUsage || !strings.Contains(errs.String(), list) || strings.Contains(out.String(), "The plan") {
			t.Errorf("%q: exit %d, %s", value, code, errs.String())
		}
		if v := strings.TrimSpace(value); v != "" && !slices.Contains(keys, v) && strings.Contains(errs.String(), v) {
			t.Errorf("%q is echoed: %s", value, errs.String())
		}
	}
	for _, args := range [][]string{{"run", "sprites", "-provider", "modal", "-y"}, {"plan", "sprites", "-provider", "modal"},
		{"plan", "kubernetes", "-provider", "modal"}, {"plan", "docker", "debian", "-provider", "modal"},
		{"scorecard", "../../test/reports/egress-refused.json", "-provider", "modal"}, {"providers", "-provider", "modal"},
		{"compare", "../../test/reports/egress-refused.json", "../../test/reports/egress-refused.json", "-provider", "modal"}} {
		var out, errs bytes.Buffer
		if code := run(args, &out, &errs); code != exitUsage || !strings.Contains(errs.String(), "-provider applies only to run exec and plan exec") {
			t.Errorf("%q: exit %d, %s", args, code, errs.String())
		}
	}
}

// PRV-17: a check the declared provider's entry excludes can't also be attested with -provider-endpoints. Every entry
// excludes all four today, so each is refused, and the fix never suggests changing the provider.
func TestExecProviderConflictsWithOptIn(t *testing.T) {
	for _, id := range []string{"SEC-4", "EGR-3", "AMP-6", "AMP-7"} {
		var out, errs bytes.Buffer
		code := run([]string{"plan", "exec", "-provider", "modal", "-provider-endpoints", id, "-o", "json", "--", "sh"}, &out, &errs)
		var e cliError
		json.Unmarshal(out.Bytes(), &e)
		if code != exitUsage || e.Code != "usage" || !strings.Contains(e.Message, "can't turn on "+id) ||
			e.Fix != "leave out -provider-endpoints for the checks that scope excludes" {
			t.Errorf("%s: exit %d, %+v", id, code, e)
		}
	}
}

// PRV-17 and AGT-3: before approval, the plan says Cloud access is not applicable under Sandprobe's reviewed scope for
// the declared provider, lists each check it keeps off with that entry's own reason, and says the operator declared
// it and Sandprobe did not verify it, in text and JSON; an unapproved run carries the same. Without -provider the plan
// is as before.
func TestExecProviderPlan(t *testing.T) {
	var out, errs bytes.Buffer
	if code := run([]string{"plan", "exec", "-provider", "modal", "--", "sh"}, &out, &errs); code != exitGraded {
		t.Fatalf("exit %d, %s", code, errs.String())
	}
	text := out.String()
	want := []string{"Provider, as the operator declared it (-provider, PRV-17)",
		"Cloud access: not applicable — Sandprobe's reviewed scope for modal excludes these provider-owned endpoints. The operator declared the provider as modal; Sandprobe did not verify it.",
		"none: AMP-6, AMP-7, EGR-3, SEC-4 stay off: Sandprobe's reviewed scope for modal excludes these provider-owned endpoints (PRV-17)",
		"The operator declared the provider as modal with -provider; Sandprobe did not verify it, and Cloud access isn't counted on that word alone (PRV-17)."}
	for id, why := range host.ModalExcluded {
		want = append(want, id+" ("+endpointNames[id]+") stays off: "+why)
	}
	for _, w := range want {
		if !strings.Contains(text, w) {
			t.Errorf("the plan lacks %q:\n%s", w, text)
		}
	}
	if strings.Contains(text, "terms exclude") || strings.Contains(text, "their terms") {
		t.Errorf("the plan claims the provider's own terms:\n%s", text)
	}
	out.Reset()
	if code := run([]string{"run", "exec", "-provider", "modal", "-o", "json", "--", "sh"}, &out, &errs); code != exitApproval {
		t.Fatalf("unapproved: exit %d, %s", code, errs.String())
	}
	var p planDoc
	if err := json.Unmarshal(out.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if !p.NeedsApproval || p.DeclaredProvider != "modal" || len(p.Declared) != 5 || !strings.Contains(p.Declared[0], report.DeclaredUnverified("modal")) ||
		!strings.Contains(p.Residual, "Sandprobe did not verify it") {
		t.Errorf("the unapproved run's JSON plan: %+v", p)
	}
	out.Reset()
	if code := run([]string{"plan", "exec", "-o", "json", "--", "sh"}, &out, &errs); code != exitGraded {
		t.Fatalf("exit %d", code)
	}
	if strings.Contains(out.String(), "declared") || strings.Contains(out.String(), "reviewed scope") {
		t.Errorf("a plan without -provider names a declaration:\n%s", out.String())
	}
}

// OUT-4 and PRV-17: -min 6 can never pass once a declared provider makes the score out of 5, so it is refused before
// anything runs in the box; without -provider, and with -min full, it isn't.
func TestExecProviderMinSix(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	var out, errs bytes.Buffer
	code := run([]string{"run", "exec", "-provider", "modal", "-min", "6", "-no-canary", "-y", "--", "sh", "-c", "touch " + marker + "; cat >/dev/null"}, &out, &errs)
	if code != exitUsage || !strings.Contains(errs.String(), report.DeclaredUnverified("modal")) || !strings.Contains(errs.String(), "use -min full") {
		t.Errorf("exit %d, %s", code, errs.String())
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("the box's command ran before -min 6 was refused")
	}
	for _, args := range [][]string{{"run", "exec", "-min", "6", "--", "sh"}, {"run", "exec", "-provider", "modal", "-min", "full", "--", "sh"}} {
		errs.Reset()
		if code := run(args, &out, &errs); code != exitApproval {
			t.Errorf("%q: exit %d, %s", args, code, errs.String())
		}
	}
}

// PRV-17, SCR-2 and SCR-3: a saved run exec report that declares modal reads out of five, Cloud access not applicable
// under Sandprobe's reviewed scope for modal with Modal's own reasons, and every human-readable rendering says the
// operator declared it and Sandprobe did not verify it: the scorecard, the run's summary and both pages. The card's
// JSON carries the name.
func TestScorecardDeclaredProvider(t *testing.T) {
	in, d := declaredSaved(t, "modal")
	unverified := report.DeclaredUnverified("modal")
	var out, errs bytes.Buffer
	if code := run([]string{"scorecard", in}, &out, &errs); code != exitGraded {
		t.Fatalf("exit %d, %s", code, errs.String())
	}
	line := "Cloud access isn't counted: Sandprobe's reviewed scope for modal excludes these provider-owned endpoints (" +
		host.ModalExcluded["SEC-4"] + "; " + host.ModalExcluded["AMP-7"] + "). " + unverified + "."
	if s := flat(out.String()); !strings.Contains(s, "Score 2/5") || !strings.Contains(s, flat(line)) || !strings.Contains(s, flat(report.NotApplicableWhy("modal", true))) {
		t.Errorf("the scorecard:\n%s", out.String())
	}
	out.Reset()
	if code := run([]string{"scorecard", in, "-o", "json"}, &out, &errs); code != exitGraded {
		t.Fatalf("json exit %d", code)
	}
	var c report.Card
	if err := json.Unmarshal(out.Bytes(), &c); err != nil {
		t.Fatal(err)
	}
	if r := c.Rows[4]; c.Of != 5 || !r.NotApplicable || r.DeclaredProvider != "modal" || r.Scope != "modal" || !strings.Contains(r.Terms, host.ModalExcluded["SEC-4"]) {
		t.Errorf("the card's JSON: %d/%d %+v", c.Score, c.Of, r)
	}
	dir := t.TempDir()
	if code := run([]string{"scorecard", in, "-out", dir}, &out, &errs); code != exitGraded {
		t.Fatalf("-out exit %d", code)
	}
	pages, _ := filepath.Glob(filepath.Join(dir, "*.html"))
	if len(pages) != 1 {
		t.Fatalf("pages: %v", pages)
	}
	saved, _ := os.ReadFile(pages[0])
	page, err := report.HTML(d, "")
	if err != nil {
		t.Fatal(err)
	}
	summary := renderResult(d, "sandprobe-exec-"+d.Run.ID, true, termCaps{width: 80})
	for surface, s := range map[string]string{"the re-rendered page": html.UnescapeString(string(saved)), "the run's page": html.UnescapeString(string(page)), "the run's summary": summary} {
		if !strings.Contains(flat(s), unverified) || !strings.Contains(flat(s), "Sandprobe's reviewed scope for modal") {
			t.Errorf("%s doesn't say the operator declared modal and Sandprobe didn't verify it", surface)
		}
	}
}

// ANL-1 and PRV-17: a saved report is refused, never read out of five, when its declared provider and its kinds don't
// agree with this binary's own table, or the declaration sits where only run exec writes one. Scored directly, a
// report whose kinds differ from the entry's never reads out of five.
func TestScorecardRefusesForgedDeclaredProvider(t *testing.T) {
	_, base := declaredSaved(t, "modal")
	clone := func() report.Doc {
		b, _ := json.Marshal(base)
		var d report.Doc
		json.Unmarshal(b, &d)
		return d
	}
	for name, tc := range map[string]struct {
		edit   func(d *report.Doc)
		scored bool // report.Score on the edited report must stay out of six
	}{
		"provider_terms with no declared provider": {func(d *report.Doc) { d.Manifest.DeclaredProvider = ""; d.Schema = report.SchemaFor(d.Manifest) }, true},
		"a kind turned opt_in":                     {func(d *report.Doc) { d.Manifest.SkipKinds["SEC-4"] = obs.SkipOptIn }, true},
		"a kind removed":                           {func(d *report.Doc) { delete(d.Manifest.SkipKinds, "AMP-7") }, true},
		"an excluded check attested": {func(d *report.Doc) {
			delete(d.Manifest.SkipKinds, "SEC-4")
			d.Manifest.Attested = []string{"SEC-4"}
			for i := range d.Checks {
				if d.Checks[i].ID == "SEC-4" {
					d.Checks[i].Attestation = report.Attestation
				}
			}
		}, true},
		"an excluded check run": {func(d *report.Doc) {
			delete(d.Manifest.SkipKinds, "SEC-4")
			delete(d.Manifest.Skipped, "SEC-4")
			d.Manifest.Selected = append(d.Manifest.Selected, "SEC-4")
			for i := range d.Checks {
				if d.Checks[i].ID == "SEC-4" {
					d.Checks[i].Result, d.Checks[i].Reason = obs.NotFound, ""
				}
			}
		}, true},
		"a provider the binary doesn't know":    {func(d *report.Doc) { d.Manifest.DeclaredProvider = "nope" }, true},
		"aws-nitro, which has no PRV-row entry": {func(d *report.Doc) { d.Manifest.DeclaredProvider = "aws-nitro" }, true},
		"exec declaring exec":                   {func(d *report.Doc) { d.Manifest.DeclaredProvider = "exec" }, true},
		"a differently cased key":               {func(d *report.Doc) { d.Manifest.DeclaredProvider = "Modal" }, true},
		"on a Sprites report":                   {func(d *report.Doc) { d.Run.Provider = "sprites" }, false},
		"under sandprobe/2":                     {func(d *report.Doc) { d.Schema = report.SchemaSkipKinds }, false},
		"with EVD-10's protocol": {func(d *report.Doc) {
			d.Manifest.CanaryTCP80Protocol = canary.HTTPMarkerV1
		}, false},
	} {
		d := clone()
		tc.edit(&d)
		in := writeDoc(t, d)
		var out, errs bytes.Buffer
		if code := run([]string{"scorecard", in}, &out, &errs); code != exitUsage || strings.Contains(out.String(), "/5") {
			t.Errorf("%s: exit %d\n%s", name, code, out.String())
		}
		if c := report.Score(d); tc.scored && (c.Of != 6 || c.Rows[4].NotApplicable) {
			t.Errorf("%s: scored directly %d/%d %+v", name, c.Score, c.Of, c.Rows[4])
		}
	}
	for name, raw := range map[string]string{"empty": `"declared_provider":""`, "null": `"declared_provider":null`} {
		b, _ := json.Marshal(base)
		b = bytes.Replace(b, []byte(`"declared_provider":"modal"`), []byte(raw), 1)
		in := filepath.Join(t.TempDir(), "report.json")
		os.WriteFile(in, b, 0o644)
		var out, errs bytes.Buffer
		if code := run([]string{"scorecard", in}, &out, &errs); code != exitUsage {
			t.Errorf("present but %s: exit %d", name, code)
		}
	}
}

// CMP-1 and PRV-17: any change to a declared provider is a changed setup, never like-for-like and never an
// improvement, even when the provider_terms skips are the same; the same declaration on both sides is a matched pair.
func TestCompareDeclaredProvider(t *testing.T) {
	optIn := skipSaved(t, "exec", host.Options{Excluded: host.ExecExclusions(), ExcludedKind: obs.SkipOptIn})
	modal, _ := declaredSaved(t, "modal")
	sprites, _ := declaredSaved(t, "sprites")
	for name, tc := range map[string]struct {
		before, after string
		code          int
	}{
		"undeclared, then modal":   {optIn, modal, exitPartial},
		"modal, then undeclared":   {modal, optIn, exitPartial},
		"modal, then sprites":      {modal, sprites, exitPartial},
		"modal in both, matched":   {modal, modal, exitGraded},
		"sprites in both, matched": {sprites, sprites, exitGraded},
	} {
		var out, errs bytes.Buffer
		code := run([]string{"compare", tc.before, tc.after, "-o", "json"}, &out, &errs)
		var c struct {
			ContextChanges   []string `json:"context_changes"`
			NoObservedChange bool     `json:"no_observed_change"`
		}
		json.Unmarshal(out.Bytes(), &c)
		matched := tc.code == exitGraded
		if code != tc.code || c.NoObservedChange != matched || slices.Contains(c.ContextChanges, "declared_configuration") == matched {
			t.Errorf("%s: exit %d, %+v %s", name, code, c, errs.String())
		}
	}
}

// AGT-3 and PRV-17: the CLI's own help, the instructions an agent reads today, says the name comes only from the person
// and is never added or changed to clear a red, and lists exactly the names -provider takes.
func TestHelpSaysTheProviderComesFromThePerson(t *testing.T) {
	var out, errs bytes.Buffer
	run([]string{"help"}, &out, &errs)
	s := flat(out.String())
	for _, w := range []string{"It is the operator's word, never verified.", "The name comes only from your person: an agent never infers it from the command, a hostname, the environment or a report, and never adds or changes it to turn a red category into not applicable.",
		"one of " + strings.Join(host.DeclarableProviders()[:len(host.DeclarableProviders())-1], ", ") + " or " + host.DeclarableProviders()[len(host.DeclarableProviders())-1] + "."} {
		if !strings.Contains(s, w) {
			t.Errorf("the help lacks %q", w)
		}
	}
}

// PRV-17 and AGT-3: no remediation text suggests -provider: not the catalog's advice and fixes, not explain, not any
// rendering of a run exec report that declares nothing (whose Cloud access reads "Not tested"), and not the fix of an
// error that -provider didn't cause.
func TestNothingSuggestsProvider(t *testing.T) {
	suggests := func(s string) bool {
		return strings.Contains(strings.ReplaceAll(s, "-provider-endpoints", ""), "-provider")
	}
	for id, a := range catalog.Guide {
		if suggests(a.Gets + a.Fix + a.Mark) {
			t.Errorf("the catalog's advice for %s suggests -provider", id)
		}
	}
	optIn := skipSaved(t, "exec", host.Options{Excluded: host.ExecExclusions(), ExcludedKind: obs.SkipOptIn})
	b, _ := os.ReadFile(optIn)
	var d report.Doc
	json.Unmarshal(b, &d)
	page, _ := report.HTML(d, "")
	surfaces := map[string]string{"the page": string(page), "the run's summary": renderResult(d, "x", true, termCaps{width: 80})}
	for _, args := range [][]string{{"scorecard", optIn}, {"scorecard", optIn, "-o", "json"}, {"profile", optIn}, {"compare", optIn, optIn},
		{"explain", "SEC-4"}, {"explain", "AMP-7"}, {"explain", "EGR-3"}, {"explain", "AMP-6"},
		{"plan", "exec", "-provider-endpoints", "all", "--", "sh"}, {"plan", "exec", "-provider-endpoints", "SEC-4,SEC-4", "--", "sh"},
		{"run", "exec", "-as", "bad user", "-y", "--", "sh"}, {"run", "exec", "-y"}, {"plan", "sprites", "-provider-endpoints", "SEC-4"}} {
		var out, errs bytes.Buffer
		run(args, &out, &errs)
		surfaces[strings.Join(args, " ")] = out.String() + errs.String()
	}
	for name, s := range surfaces {
		if suggests(s) {
			t.Errorf("%s suggests -provider:\n%s", name, s)
		}
	}
	if r := report.Score(d).Rows[4]; r.Why != "Not tested: opt in with -provider-endpoints SEC-4,AMP-7 if your provider's terms allow" {
		t.Errorf("Cloud access on undeclared run exec: %q", r.Why)
	}
}
