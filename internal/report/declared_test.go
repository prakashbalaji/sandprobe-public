package report

import (
	"encoding/json"
	"html"
	"maps"
	"strings"
	"testing"

	"sandprobe/internal/grade"
	"sandprobe/internal/host"
	"sandprobe/internal/obs"
)

// declared is run exec's options when the operator declares name (PRV-17): the entry's reasons in place of PRV-15's.
func declared(name string) host.Options {
	excluded := host.ExecExclusions()
	maps.Copy(excluded, host.DeclaredExclusions(name))
	return host.Options{Mode: "exec", Excluded: excluded, ExcludedKind: obs.SkipOptIn, DeclaredProvider: name, Existing: true}
}

// PRV-17 and SCR-2: for every key of this binary's PRV-row table, a run exec report declaring it declares
// sandprobe/5 and reads out of five; Cloud access is not applicable, never green, its terms from that key's entry, its
// row carrying the name, and the row, the line beside the score, the JSON and the page each say the operator declared
// it and Sandprobe did not verify it. The letter is the undeclared run's.
func TestScoreDeclaredProvider(t *testing.T) {
	undeclared := replanned(t, "exec", host.Options{Mode: "exec", Excluded: host.ExecExclusions(), ExcludedKind: obs.SkipOptIn, Existing: true})
	for name, entry := range natives {
		d := replanned(t, "exec", declared(name))
		c := Score(d)
		r := row(t, c, "Cloud access")
		unverified := DeclaredUnverified(name)
		if d.Schema != SchemaDeclaredProvider || d.Manifest.DeclaredProvider != name || c.Of != 5 || !r.NotApplicable || r.Green ||
			r.Why != NotApplicableWhy(name, true) || r.Scope != name || r.DeclaredProvider != name ||
			r.Terms != entry["SEC-4"]+"; "+entry["AMP-7"] && r.Terms != entry["SEC-4"] {
			t.Errorf("%s: %s %d/%d %+v", name, d.Schema, c.Score, c.Of, r)
		}
		if len(c.NotCounted()) != 1 || !strings.HasPrefix(c.NotCounted()[0], "Cloud access isn't counted: "+ReviewedScope(name)+" (") ||
			!strings.HasSuffix(c.NotCounted()[0], ". "+unverified+".") || !strings.Contains(r.Why, unverified) {
			t.Errorf("%s: %q, %q", name, c.NotCounted(), r.Why)
		}
		b, _ := json.Marshal(c)
		page, err := HTML(d, "")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), `"declared_provider":"`+name+`"`) || !strings.Contains(html.UnescapeString(string(page)), unverified) {
			t.Errorf("%s: the card's JSON or the page doesn't carry the declaration", name)
		}
		if d.Grade.Letter != undeclared.Grade.Letter || d.Grade.Complete != undeclared.Grade.Complete {
			t.Errorf("%s: letter %s against %s undeclared", name, d.Grade.Letter, undeclared.Grade.Letter)
		}
	}
}

// SCR-2, SCR-4 and PRV-17: a workload card is unauthenticated, so the workload page never names a provider from it.
// A native not-applicable row reads "Sandprobe's reviewed scope for the provider", never the card's stored scope and
// never "their terms", even when the stored scope is arbitrary text. A declared provider is run exec's alone: a card
// carrying one is refused, as is a scope or terms on a counted row.
func TestWorkloadPageReviewedScope(t *testing.T) {
	c := Score(replanned(t, "daytona", host.Options{Mode: "exec", Excluded: host.DaytonaExclusions(), ExcludedKind: obs.SkipProviderTerms}))
	x := WorkloadExposure{Schema: "sandprobe.workload-exposure/1", InputVerification: "proof_recomputation_unauthenticated_input", Card: c}
	for name, scope := range map[string]string{"its own scope": "daytona", "another provider's name": "sprites", "arbitrary text": "an attacker supplied scope"} {
		y := x
		y.Rows = append([]Row(nil), x.Rows...)
		y.Rows[4].Scope = scope
		if scope != "daytona" {
			y.Rows[4].Why = "Not applicable: Sandprobe's reviewed scope for " + scope + " excludes these provider-owned endpoints"
		}
		b, err := WorkloadExposureHTML(grade.WorkloadReport{}, grade.EvidenceCoverage{}, y)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		page := html.UnescapeString(string(b))
		if !strings.Contains(page, "Cloud access isn't counted: Sandprobe's reviewed scope for the provider excludes these provider-owned endpoints (") ||
			!strings.Contains(page, NotApplicableWhy("", false)) ||
			strings.Contains(page, "reviewed scope for "+scope) || strings.Contains(page, "attacker") || strings.Contains(page, "their terms") || strings.Contains(page, "terms exclude") {
			t.Errorf("%s: the workload page:\n%s", name, page)
		}
		if y.Rows[4].Scope != scope {
			t.Errorf("%s: rendering changed the caller's card", name)
		}
	}
	y := x
	y.Card = Score(replanned(t, "exec", declared("modal")))
	if validWorkloadExposure(y) {
		t.Error("a workload card carrying a declared provider was accepted")
	}
	if _, err := WorkloadExposureHTML(grade.WorkloadReport{}, grade.EvidenceCoverage{}, y); err == nil {
		t.Error("the workload page rendered a declared provider")
	}
	for name, mutate := range map[string]func(r []Row){
		"a scope on a counted row": func(r []Row) { r[0].Scope = "daytona" },
		"terms on a counted row":   func(r []Row) { r[0].Terms = "forged" },
	} {
		z := x
		z.Rows = append([]Row(nil), x.Rows...)
		mutate(z.Rows)
		if validWorkloadExposure(z) {
			t.Errorf("%s: accepted", name)
		}
	}
}
