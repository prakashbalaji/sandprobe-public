package report

import (
	"bytes"
	"encoding/json"
	"html/template"
	"maps"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"sandprobe/internal/catalog"
	"sandprobe/internal/grade"
	"sandprobe/internal/host"
	"sandprobe/internal/obs"
)

// replanned is a real Docker fixture run (test/reports/bundles) as an adapter with these options would have planned
// it: the skips and their kinds come from host.Plan, the grade from the grader and the report from Build, as a run
// writes them. A check the plan now skips loses its observation, and without a canary so do the canary's checks.
func replanned(t *testing.T, provider string, o host.Options) Doc {
	t.Helper()
	m, pd, ev := replan(t, o)
	b, _ := json.Marshal(pd)
	r := &host.Run{Manifest: m, Doc: b, Evidence: ev, Report: grade.GradeBytes(m, b, &ev)}
	d := Build(r, Meta{Version: "fixture", Provider: provider, BoxName: m.BoxID, CreatedBySandprobe: true,
		StartedAt: time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC), Duration: 4 * time.Second})
	if !d.Grade.Valid {
		t.Fatalf("%s: the replanned run is invalid: %s", provider, d.Grade.Invalid)
	}
	return d
}

// replan is replanned's manifest, the probe's document and the canary's evidence, before grading.
func replan(t *testing.T, o host.Options) (obs.Manifest, *obs.Doc, obs.CanaryEvidence) {
	t.Helper()
	raw, err := os.ReadFile("../../test/reports/bundles/egress-refused.bundle.json")
	if err != nil {
		t.Fatal(err)
	}
	var q struct {
		Manifest     obs.Manifest       `json:"manifest"`
		Observations string             `json:"observations"`
		Evidence     obs.CanaryEvidence `json:"evidence"`
	}
	if err := json.Unmarshal(raw, &q); err != nil {
		t.Fatal(err)
	}
	pd, err := obs.ParseDoc([]byte(q.Observations))
	if err != nil {
		t.Fatal(err)
	}
	plan, _ := host.Plan(o, &obs.Survey{Schema: obs.SurveySchema}, q.Manifest.BoxID, host.Storage{}, "", "", "")
	m, drop := q.Manifest, map[string]bool{}
	for id := range o.Excluded {
		drop[id] = true
		m.Skipped[id] = plan.Skipped[id]
	}
	if o.NoCanary {
		m.NoCanary, q.Evidence = true, obs.CanaryEvidence{}
		for _, id := range m.Selected {
			if ck, _ := catalog.Get(id); catalog.NeedsCanary(ck) {
				pd.Observations = slices.DeleteFunc(pd.Observations, func(ob obs.Observation) bool { return ob.ID == id })
			}
		}
		m.CheckNonces, m.Endpoints = map[string]string{}, map[string]string{}
	}
	m.Selected = slices.DeleteFunc(m.Selected, func(id string) bool { return drop[id] })
	pd.Observations = slices.DeleteFunc(pd.Observations, func(ob obs.Observation) bool { return drop[ob.ID] })
	for id := range drop {
		delete(m.Targets, id)
		delete(m.Discover, id)
		delete(m.CheckNonces, id)
		delete(m.Endpoints, id)
	}
	m.SkipKinds, m.Attested, m.DeclaredProvider = plan.SkipKinds, plan.Attested, plan.DeclaredProvider
	return m, pd, q.Evidence
}

// natives are the native adapters whose PRV rows exclude the provider's own endpoints because its terms do (PRV-5),
// by the provider name their reports record: exactly host.TermsExclusions (TestNativesAreThePolicy).
var natives = map[string]map[string]string{"e2b": host.E2BExclusions(), "daytona": host.DaytonaExclusions(),
	"vercel": host.VercelExclusions(), "cloudflare": host.CloudflareExclusions(), "boat": host.BoatExclusions(),
	"baseten": host.BasetenExclusions(), "exe.dev": host.ExedevExclusions(), "sprites": host.SpritesExclusions(),
	"modal": host.ModalExcluded}

// SCR-2: a native adapter's PRV row makes Cloud access not applicable: grey, never green, out of the score (x/5),
// named on one line with the run's own skip reasons, and the findings, their counts and completeness are the ones the
// same run gets without the rule.
func TestScoreNotApplicable(t *testing.T) {
	for provider, excluded := range natives {
		d := replanned(t, provider, host.Options{Mode: "exec", Excluded: excluded, ExcludedKind: obs.SkipProviderTerms})
		c := Score(d)
		r := row(t, c, "Cloud access")
		if !r.NotApplicable || r.Green || r.Why != NotApplicableWhy(provider, false) || r.Scope != provider || r.DeclaredProvider != "" ||
			!strings.Contains(r.Terms, excluded["SEC-4"]) || !strings.Contains(r.Terms, excluded["AMP-7"]) {
			t.Errorf("%s: Cloud access %+v", provider, r)
		}
		if c.Of != 5 || c.Score > 5 || len(c.NotCounted()) != 1 || !strings.HasPrefix(c.NotCounted()[0], "Cloud access isn't counted: Sandprobe's reviewed scope for "+provider+" excludes these provider-owned endpoints (") {
			t.Errorf("%s: score %d/%d, line %q", provider, c.Score, c.Of, c.NotCounted())
		}
		// SCR-2, PRV-5: Sandprobe's reviewed scope, never a claim about the provider's own terms, and no declaration.
		if s := r.Why + c.NotCounted()[0]; strings.Contains(s, "their terms") || strings.Contains(s, "terms exclude") || strings.Contains(s, "declared") {
			t.Errorf("%s: %q", provider, s)
		}
		for _, other := range c.Rows {
			if other.Name != "Cloud access" && other.NotApplicable {
				t.Errorf("%s: %s is not applicable too", provider, other.Name)
			}
		}
		plain := replanned(t, provider, host.Options{Mode: "exec", Excluded: excluded}) // the same skips, no kind
		if !reflect.DeepEqual(d.Findings, plain.Findings) || !reflect.DeepEqual(d.Grade, plain.Grade) || len(d.Findings) == 0 || Score(plain).Of != 6 {
			t.Errorf("%s: findings %+v and grade %+v, against %+v and %+v without the rule", provider, d.Findings, d.Grade, plain.Findings, plain.Grade)
		}
		b, _ := json.Marshal(c)
		if !strings.Contains(string(b), `"of":5`) || !strings.Contains(string(b), `"not_applicable":true`) {
			t.Errorf("%s: the card's JSON: %s", provider, b)
		}
		page, err := HTML(d, "modern")
		if err != nil {
			t.Fatal(err)
		}
		p := string(page)
		if !strings.Contains(p, "<span>/5</span>") || strings.Contains(p, "<span>/6</span>") || !strings.Contains(p, `class="cat na"`) ||
			!strings.Contains(p, "NOT APPLICABLE") || !strings.Contains(p, "Cloud access isn&#39;t counted: ") || strings.Contains(p, "From a saved report") {
			t.Errorf("%s: the page doesn't show Cloud access as not applicable out of 5", provider)
		}
	}
}

// SCR-2: run exec's and a recipe's default exclusions are opt-in, so Cloud access stays red and "Not tested", out of
// six, and says how to opt in.
func TestScoreOptInStaysNotTested(t *testing.T) {
	recipe := map[string]string{}
	for _, id := range []string{"SEC-4", "EGR-3", "AMP-6", "AMP-7"} {
		recipe[id] = "the kubernetes recipe keeps checks that contact the provider's own endpoints off (RCP-4)"
	}
	for provider, excluded := range map[string]map[string]string{"exec": host.ExecExclusions(), "kubernetes": recipe} {
		c := Score(replanned(t, provider, host.Options{Mode: "exec", Excluded: excluded, ExcludedKind: obs.SkipOptIn}))
		r := row(t, c, "Cloud access")
		if r.NotApplicable || r.Green || r.Why != "Not tested: opt in with -provider-endpoints SEC-4,AMP-7 if your provider's terms allow" {
			t.Errorf("%s: Cloud access %+v", provider, r)
		}
		if c.Of != 6 || len(c.NotCounted()) != 0 {
			t.Errorf("%s: score %d/%d, line %q", provider, c.Score, c.Of, c.NotCounted())
		}
	}
}

// SCR-2 and HCN-5: without a canary, Exfiltration stays "not tested: run without a canary", red, and the run
// incomplete; Cloud access keeps its opt-in reason, and nothing leaves the score.
func TestScoreNoCanaryIsNeverNotApplicable(t *testing.T) {
	d := replanned(t, "exec", host.Options{Mode: "exec", Excluded: host.ExecExclusions(), ExcludedKind: obs.SkipOptIn, NoCanary: true})
	c := Score(d)
	if r := row(t, c, "Exfiltration"); r.Green || r.NotApplicable || r.Why != "Not tested: run without a canary" {
		t.Errorf("Exfiltration: %+v", r)
	}
	if d.Grade.Complete || c.Of != 6 || !strings.HasPrefix(row(t, c, "Cloud access").Why, "Not tested: opt in") {
		t.Errorf("complete %v, score %d/%d", d.Grade.Complete, c.Score, c.Of)
	}
}

// SCR-2 and GRD-5: only the host's own provider-terms kind, beside its own skip, makes a category not applicable.
func TestNotApplicableNeedsTheHostsKind(t *testing.T) {
	native := host.Options{Mode: "exec", Excluded: host.E2BExclusions()}
	if r := row(t, Score(replanned(t, "e2b", native)), "Cloud access"); r.NotApplicable || r.Why != "Not tested" {
		t.Errorf("a skip without a kind (an older report, a managed runner's audit scope): %+v", r)
	}
	terms := map[string]string{"SEC-4": obs.SkipProviderTerms, "AMP-7": obs.SkipProviderTerms}
	for name, tc := range map[string]struct {
		checks  map[string]Check
		skipped map[string]string
		unknown []string
	}{
		"skipped rows the manifest never skipped": {map[string]Check{"SEC-4": {Result: obs.Skipped}, "AMP-7": {Result: obs.Skipped}}, nil, nil},
		"skipped with an empty reason": {map[string]Check{"SEC-4": {Result: obs.Skipped}, "AMP-7": {Result: obs.Skipped}},
			map[string]string{"SEC-4": "", "AMP-7": ""}, nil},
		"one check tested": {map[string]Check{"SEC-4": {Result: obs.Skipped}, "AMP-7": {Result: obs.Finding, Severity: "medium"}},
			map[string]string{"SEC-4": "terms"}, nil},
		"one check unknown": {map[string]Check{"SEC-4": {Result: obs.Skipped}, "AMP-7": {Result: obs.Skipped}},
			map[string]string{"SEC-4": "terms", "AMP-7": "terms"}, []string{"AMP-7"}},
		"a check missing": {map[string]Check{"SEC-4": {Result: obs.Skipped}}, map[string]string{"SEC-4": "terms"}, nil},
		"the report's word alone, on run exec": {map[string]Check{"SEC-4": {Result: obs.Skipped}, "AMP-7": {Result: obs.Skipped}},
			map[string]string{"SEC-4": "terms", "AMP-7": "terms"}, nil},
	} {
		d := doc(obs.Pass, tc.checks)
		d.Run.Provider = "sprites" // the policy would allow it: each case fails for its own reason
		if strings.HasPrefix(name, "the report's word alone") {
			d.Run.Provider = "exec" // SCR-2: exec's policy is opt_in, whatever the manifest says
		}
		if name == "a check missing" {
			d.Checks = slices.DeleteFunc(d.Checks, func(c Check) bool { return c.ID == "AMP-7" })
		}
		d.Manifest.Skipped, d.Manifest.SkipKinds, d.Grade.Unknown = tc.skipped, maps.Clone(terms), tc.unknown
		if c := Score(d); row(t, c, "Cloud access").NotApplicable || c.Of != 6 {
			t.Errorf("%s: %+v", name, row(t, c, "Cloud access"))
		}
	}
	// The box can't skip a check: a "skipped" answer, or any answer for a check the host skipped, invalidates the run.
	for _, id := range []string{"SEC-4", "AMP-7"} {
		m, pd, ev := replan(t, host.Options{Mode: "exec", Excluded: host.E2BExclusions(), ExcludedKind: obs.SkipProviderTerms})
		if r := grade.Grade(m, pd, &ev); !r.Valid {
			t.Fatalf("the baseline is invalid: %s", r.Invalid)
		}
		pd.Observations = append(pd.Observations, obs.Observation{ID: id, Result: obs.NotFound})
		if r := grade.Grade(m, pd, &ev); r.Valid {
			t.Errorf("an answer for %s, which the host skipped, was accepted", id)
		}
		m, pd, ev = replan(t, host.Options{Mode: "exec"})
		if r := grade.Grade(m, pd, &ev); !r.Valid {
			t.Fatalf("the baseline is invalid: %s", r.Invalid)
		}
		for i := range pd.Observations {
			if pd.Observations[i].ID == id {
				pd.Observations[i].Result = obs.Skipped
			}
		}
		if r := grade.Grade(m, pd, &ev); r.Valid {
			t.Errorf("the box skipping %s was accepted", id)
		}
	}
}

// SCR-2 and SCR-4: a workload exposure card keeps Of honest: out of the applicable categories, and a not-applicable
// row is never green and never found or unknown.
func TestWorkloadExposureNotApplicable(t *testing.T) {
	c := Score(replanned(t, "daytona", host.Options{Mode: "exec", Excluded: host.DaytonaExclusions(), ExcludedKind: obs.SkipProviderTerms}))
	x := WorkloadExposure{Schema: "sandprobe.workload-exposure/1", InputVerification: "proof_recomputation_unauthenticated_input", Card: c}
	if !validWorkloadExposure(x) {
		t.Fatal("an honest not-applicable card was refused")
	}
	for name, mutate := range map[string]func(*Card){
		"out of six":             func(c *Card) { c.Of = 6 },
		"green":                  func(c *Card) { c.Rows[4].Green, c.Score = true, c.Score+1 },
		"another row":            func(c *Card) { c.Rows[0].NotApplicable, c.Of = true, c.Of-1 },
		"unknown":                func(c *Card) { c.Rows[4].Unknown = []string{"SEC-4"} },
		"not applicable gone":    func(c *Card) { c.Rows[4].NotApplicable = false },
		"terms on a counted row": func(c *Card) { c.Rows[0].Terms = "forged" },
	} {
		y := x
		y.Card = Score(replanned(t, "daytona", host.Options{Mode: "exec", Excluded: host.DaytonaExclusions(), ExcludedKind: obs.SkipProviderTerms}))
		mutate(&y.Card)
		if validWorkloadExposure(y) {
			t.Errorf("%s: a forged card was accepted", name)
		}
	}
}

// SCR-2's headline: a clean box on a provider whose terms exclude Cloud access reads 5/5, never 6/6, and Cloud
// access is never green, in the card, its JSON and the page.
func TestCleanBoxReadsFiveOfFive(t *testing.T) {
	d := doc(obs.Pass, map[string]Check{"SEC-4": {Result: obs.Skipped}, "AMP-7": {Result: obs.Skipped}})
	why := host.SpritesExclusions()["SEC-4"]
	d.Run.Provider = "sprites"
	d.Manifest.Skipped = map[string]string{"SEC-4": why, "AMP-7": why}
	d.Manifest.SkipKinds = map[string]string{"SEC-4": obs.SkipProviderTerms, "AMP-7": obs.SkipProviderTerms}
	c := Score(d)
	if c.Score != 5 || c.Of != 5 || row(t, c, "Cloud access").Green {
		t.Fatalf("want 5/5 with Cloud access not green, got %d/%d %+v", c.Score, c.Of, row(t, c, "Cloud access"))
	}
	b, _ := json.Marshal(c)
	if s := string(b); !strings.Contains(s, `"score":5,"of":5`) || strings.Contains(s, `"score":6`) || strings.Contains(s, `"of":6`) {
		t.Errorf("the card's JSON: %s", b)
	}
	page, err := HTML(d, "modern")
	if err != nil {
		t.Fatal(err)
	}
	if p := string(page); !strings.Contains(p, `aria-label="Score 5 of 5"><b>5</b><span>/5</span>`) || strings.Contains(p, "<span>/6</span>") {
		t.Error("the page doesn't read 5/5")
	}
}

// AGT-6, OUT-1 and GRD-1: every report Build writes declares sandprobe/6 and marshals no letter, whatever its
// manifest carries (skip kinds, attestations, a declared provider or none) and whether the run is valid or not.
// BuildLegacy, the one writer left for the earlier versions, declares the lowest of them the manifest's fields need
// and writes the grader's letter, empty on an invalid run, as before.
func TestReportSchemaVersions(t *testing.T) {
	off := host.ExecExclusions()
	delete(off, "AMP-7")
	for name, tc := range map[string]struct {
		provider string
		o        host.Options
		legacy   string
	}{
		"skip kinds, provider terms": {"e2b", host.Options{Mode: "exec", Excluded: host.E2BExclusions(), ExcludedKind: obs.SkipProviderTerms}, SchemaSkipKinds},
		"skip kinds, opt-in":         {"exec", host.Options{Mode: "exec", Excluded: host.ExecExclusions(), ExcludedKind: obs.SkipOptIn}, SchemaSkipKinds},
		"no kind":                    {"e2b", host.Options{Mode: "exec", Excluded: host.E2BExclusions()}, Schema},
		"one attested":               {"exec", host.Options{Mode: "exec", Excluded: off, ExcludedKind: obs.SkipOptIn, Attested: []string{"AMP-7"}, Existing: true}, SchemaSkipKinds},
		"all attested, no kinds":     {"exec", host.Options{Mode: "exec", ExcludedKind: obs.SkipOptIn, Attested: []string{"SEC-4", "EGR-3", "AMP-6", "AMP-7"}, Existing: true}, SchemaSkipKinds},
		"a declared provider":        {"exec", declared("modal"), SchemaDeclaredProvider},
	} {
		m, pd, ev := replan(t, tc.o)
		b, _ := json.Marshal(pd)
		for _, invalid := range []bool{false, true} {
			r := &host.Run{Manifest: m, Doc: b, Evidence: ev, Report: grade.GradeBytes(m, b, &ev)}
			if invalid {
				r.Report = grade.Report{Invalid: "a duplicate check ID"}
			}
			if r.Report.Valid == invalid || r.Report.Valid && r.Report.Letter == "" {
				t.Fatalf("%s: the grader's run: valid %v, letter %q", name, r.Report.Valid, r.Report.Letter)
			}
			d := Build(r, Meta{Provider: tc.provider})
			out, _ := json.Marshal(d)
			if d.Schema != SchemaNoLetter || SchemaNoLetter != "sandprobe/6" || d.Grade.Letter != nil || strings.Contains(string(out), `"letter"`) ||
				!strings.Contains(string(out), `"schema":"sandprobe/6"`) {
				t.Errorf("%s, invalid %v: Build declares %s with a letter in %s", name, invalid, d.Schema, out[:min(len(out), 200)])
			}
			old := BuildLegacy(r, Meta{Provider: tc.provider})
			out, _ = json.Marshal(old)
			if old.Schema != tc.legacy || old.Grade.Letter == nil || *old.Grade.Letter != r.Report.Letter ||
				!strings.Contains(string(out), `"grade":{"letter":"`+r.Report.Letter+`",`) {
				t.Errorf("%s, invalid %v: BuildLegacy declares %s, want %s with the letter %q", name, invalid, old.Schema, tc.legacy, r.Report.Letter)
			}
			old.Schema, old.Grade.Letter = d.Schema, nil
			if !reflect.DeepEqual(old, d) {
				t.Errorf("%s, invalid %v: the two differ in more than the version and the letter", name, invalid)
			}
		}
		if strings.Contains(name, "no kind") && len(m.SkipKinds) != 0 {
			t.Error("a report with no kind carries SkipKinds")
		}
	}
	if Schema != "sandprobe/1" || !slices.Equal(Schemas, []string{"sandprobe/1", "sandprobe/2", "sandprobe/3", "sandprobe/4", "sandprobe/5", "sandprobe/6", "sandprobe/7"}) {
		t.Errorf("the versions this build reads: %v", Schemas)
	}
}

// SCR-2: the native adapters the tests treat as provider-terms are exactly the binary's own policy, and the policy
// derives opt-in for run exec and the shipped recipe, and nothing for any other provider.
func TestNativesAreThePolicy(t *testing.T) {
	for provider := range natives {
		if _, ok := host.TermsExclusions[provider]; !ok {
			t.Errorf("%s isn't in the policy", provider)
		}
	}
	if len(natives) != len(host.TermsExclusions) {
		t.Errorf("the policy has %d providers, the tests %d", len(host.TermsExclusions), len(natives))
	}
	for provider, want := range map[string]string{"sprites": obs.SkipProviderTerms, "exec": obs.SkipOptIn, "kubernetes": obs.SkipOptIn,
		"docker": "", "aws-nitro": "", "": ""} {
		if got := PolicyKinds(provider)["AMP-7"]; got != want {
			t.Errorf("%q: AMP-7 %q, want %q", provider, got, want)
		}
	}
	// PRV-17: a run exec report's declared provider takes that entry's kinds; a name the table lacks, or a declaration
	// beside any other provider, derives nothing new.
	for _, tc := range []struct{ provider, declared, want string }{{"exec", "modal", obs.SkipProviderTerms}, {"exec", "", obs.SkipOptIn},
		{"exec", "aws-nitro", obs.SkipOptIn}, {"exec", "Modal", obs.SkipOptIn}, {"exec", "exec", obs.SkipOptIn},
		{"sprites", "modal", obs.SkipProviderTerms}, {"aws-nitro", "modal", ""}, {"kubernetes", "modal", obs.SkipOptIn}} {
		if got := PolicyFor(tc.provider, tc.declared); got["SEC-4"] != tc.want || got["AMP-7"] != tc.want {
			t.Errorf("%q declaring %q: %v, want %q", tc.provider, tc.declared, got, tc.want)
		}
	}
}

// PRV-15: the report records the person's attestation beside each check -provider-endpoints turned on, and only
// there, in the JSON and on the page; the checks run as for a provider that allows them and stay find-only.
func TestReportRecordsAttestation(t *testing.T) {
	off := host.ExecExclusions()
	delete(off, "SEC-4")
	delete(off, "AMP-7")
	d := replanned(t, "exec", host.Options{Mode: "exec", Excluded: off, ExcludedKind: obs.SkipOptIn, Attested: []string{"SEC-4", "AMP-7"}, Existing: true})
	for _, c := range d.Checks {
		attested := c.ID == "SEC-4" || c.ID == "AMP-7"
		if (c.Attestation == Attestation) != attested || !attested && c.Attestation != "" {
			t.Errorf("%s: attestation %q", c.ID, c.Attestation)
		}
		if attested && (c.Result == obs.Pass || c.Result == obs.Absent || c.Result == obs.Skipped) {
			t.Errorf("%s: %s", c.ID, c.Result)
		}
	}
	if r := row(t, Score(d), "Cloud access"); r.NotApplicable || strings.HasPrefix(r.Why, "Not tested") {
		t.Errorf("Cloud access: %+v", r)
	}
	page, err := HTML(d, "modern")
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(page), template.HTMLEscapeString(Attestation)); n != 4 { // beside each test, and in the appendix
		t.Errorf("the page shows the attestation %d times, want 4", n)
	}
}

// RCP-4 and SCR-2: the policy for a person's own recipe ("recipe") is PRV-15's four as opt-in, whatever provider its
// header or a manifest names, so Cloud access is counted and reads "Not tested", never not applicable.
func TestOwnRecipePolicy(t *testing.T) {
	for _, declared := range []string{"", "modal", "recipe"} {
		got := PolicyFor(host.OwnRecipeProvider, declared)
		if len(got) != 4 {
			t.Errorf("declaring %q: %v", declared, got)
		}
		for _, id := range host.RecipeDefaultExclusions {
			if got[id] != obs.SkipOptIn {
				t.Errorf("declaring %q: %s is %q", declared, id, got[id])
			}
		}
	}
	excluded := map[string]string{}
	for _, id := range host.RecipeDefaultExclusions {
		excluded[id] = "your own recipe keeps it off"
	}
	c := Score(replanned(t, host.OwnRecipeProvider, host.Options{Mode: "exec", Excluded: excluded, ExcludedKind: obs.SkipOptIn}))
	if r := row(t, c, "Cloud access"); r.NotApplicable || r.Green || !strings.HasPrefix(r.Why, "Not tested") || c.Of != 6 || len(c.NotCounted()) != 0 {
		t.Errorf("Cloud access %+v, out of %d, %v", r, c.Of, c.NotCounted())
	}
}

// RCP-4 and AGT-6: Build writes run.recipe for a run through a person's own recipe, as exactly own and the SHA-256,
// under sandprobe/7; and no recipe key, under sandprobe/6, for any other run, a shipped recipe's included. The page
// re-rendered from a saved report embeds a sandprobe/7 report as sandprobe/7, and an older one as sandprobe/6.
func TestOwnRecipeRecordWritten(t *testing.T) {
	sha := strings.Repeat("0123456789abcdef", 4)
	m, pd, ev := replan(t, host.Options{Mode: "exec", Excluded: host.ExecExclusions(), ExcludedKind: obs.SkipOptIn})
	b, _ := json.Marshal(pd)
	r := &host.Run{Manifest: m, Doc: b, Evidence: ev, Report: grade.GradeBytes(m, b, &ev)}
	for provider, own := range map[string]string{host.OwnRecipeProvider: sha, "kubernetes": "", "exec": ""} {
		d := Build(r, Meta{Version: "fixture", Provider: provider, BoxName: m.BoxID, CreatedBySandprobe: true, OwnRecipeSHA256: own})
		raw, _ := json.Marshal(d)
		var tree struct {
			Run map[string]json.RawMessage `json:"run"`
		}
		if err := json.Unmarshal(raw, &tree); err != nil {
			t.Fatal(err)
		}
		got, has := tree.Run["recipe"]
		if want := `{"own":true,"sha256":"` + sha + `"}`; own != "" && string(got) != want || own == "" && has {
			t.Errorf("%s: run.recipe is %s", provider, got)
		}
		want := SchemaNoLetter
		if own != "" {
			want = SchemaOwnRecipe
		}
		if d.Schema != want {
			t.Errorf("%s: %s", provider, d.Schema)
		}
		page, err := SavedHTML(d, "graphite")
		if err != nil || !bytes.Contains(page, []byte(`"schema":"`+want+`"`)) || (own != "") != bytes.Contains(page, []byte(`"recipe":{"own":true,"sha256":"`+sha+`"}`)) {
			t.Errorf("%s: the re-rendered page doesn't embed the report as %s: %v", provider, want, err)
		}
		letter := "F"
		d.Schema, d.Grade.Letter, d.Run.Recipe = SchemaSkipKinds, &letter, nil
		if page, err := SavedHTML(d, "graphite"); err != nil || !bytes.Contains(page, []byte(`"schema":"sandprobe/6"`)) || bytes.Contains(page, []byte(`"letter"`)) {
			t.Errorf("%s: an older report isn't embedded as sandprobe/6 without its letter: %v", provider, err)
		}
	}
}
