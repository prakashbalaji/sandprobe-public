package report

import (
	"encoding/json"
	"html"
	"maps"
	"reflect"
	"slices"
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
// sandprobe/6 and reads out of five; Cloud access is not applicable, never green, its terms from that key's entry, its
// row carrying the name, and the row, the line beside the score, the JSON and the page each say the operator declared
// it and Sandprobe did not verify it. The findings and completeness are the undeclared run's.
func TestScoreDeclaredProvider(t *testing.T) {
	undeclared := replanned(t, "exec", host.Options{Mode: "exec", Excluded: host.ExecExclusions(), ExcludedKind: obs.SkipOptIn, Existing: true})
	for name, entry := range natives {
		d := replanned(t, "exec", declared(name))
		c := Score(d)
		r := row(t, c, "Cloud access")
		unverified := DeclaredUnverified(name)
		if d.Schema != SchemaNoLetter || d.Manifest.DeclaredProvider != name || c.Of != 5 || !r.NotApplicable || r.Green ||
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
		if !reflect.DeepEqual(d.Findings, undeclared.Findings) || !reflect.DeepEqual(d.Grade, undeclared.Grade) || len(d.Findings) == 0 {
			t.Errorf("%s: findings %+v and grade %+v, against %+v and %+v undeclared", name, d.Findings, d.Grade, undeclared.Findings, undeclared.Grade)
		}
	}
}

// SCR-2, SCR-4 and PRV-17: the workload page states Sandprobe's reviewed scope for a native adapter's not-applicable
// row, never the provider's own terms, and a legacy card that names no scope still reads without one. A declared
// provider is run exec's alone: a workload exposure card carrying one is refused, so the page never shows it.
func TestWorkloadPageReviewedScope(t *testing.T) {
	c := Score(replanned(t, "daytona", host.Options{Mode: "exec", Excluded: host.DaytonaExclusions(), ExcludedKind: obs.SkipProviderTerms}))
	x := WorkloadExposure{Schema: "sandprobe.workload-exposure/1", InputVerification: "proof_recomputation_unauthenticated_input", Card: c}
	b, err := WorkloadExposureHTML(grade.WorkloadReport{}, grade.EvidenceCoverage{}, x)
	if err != nil {
		t.Fatal(err)
	}
	page := html.UnescapeString(string(b))
	if !strings.Contains(page, "Cloud access isn't counted: Sandprobe's reviewed scope for daytona excludes these provider-owned endpoints (") ||
		strings.Contains(page, "their terms") || strings.Contains(page, "terms exclude") {
		t.Errorf("the workload page:\n%s", page)
	}
	legacy := x
	legacy.Rows = append([]Row(nil), x.Rows...)
	legacy.Rows[4].Scope, legacy.Rows[4].Why = "", LegacyNotApplicable // exactly what 0.3.0 wrote
	if lines := legacy.NotCounted(); len(lines) != 1 || !strings.HasPrefix(lines[0], "Cloud access isn't counted: Sandprobe's reviewed scope for the provider excludes") {
		t.Errorf("a legacy card: %q", lines)
	}
	if !validWorkloadExposure(legacy) {
		t.Error("a legacy card was refused")
	}
	if b, err := WorkloadExposureHTML(grade.WorkloadReport{}, grade.EvidenceCoverage{}, legacy); err != nil ||
		strings.Contains(html.UnescapeString(string(b)), "their terms") || !strings.Contains(html.UnescapeString(string(b)), NotApplicableWhy("daytona", false)) {
		t.Errorf("a legacy card renders its stored wording, or fails: %v", err)
	}
	y := x
	y.Card = Score(replanned(t, "exec", declared("modal")))
	if validWorkloadExposure(y) {
		t.Error("a workload card carrying a declared provider was accepted")
	}
	if _, err := WorkloadExposureHTML(grade.WorkloadReport{}, grade.EvidenceCoverage{}, y); err == nil {
		t.Error("the workload page rendered a declared provider")
	}
	// The security review of 5d4e8c6: a stored scope is the card's word, so only a key of this binary's table whose
	// entry derives the row's own reason and terms is accepted; anything else is refused, never rendered.
	for name, mutate := range map[string]func(r []Row){
		"an arbitrary scope":           func(r []Row) { r[4].Scope = "an attacker supplied scope" },
		"another real provider's name": func(r []Row) { r[4].Scope = "sprites" },
		"a key with no reasons to match": func(r []Row) {
			r[4].Scope, r[4].Why = "sprites", NotApplicableWhy("sprites", false)
		},
		"its own name, edited terms":  func(r []Row) { r[4].Terms = "forged reasons" },
		"its own name, edited reason": func(r []Row) { r[4].Why = "Not applicable: trust me" },
		"a differently cased key":     func(r []Row) { r[4].Scope = "Daytona" },
		"a scope on a counted row":    func(r []Row) { r[0].Scope = "daytona" },
		"a declared provider":         func(r []Row) { r[4].DeclaredProvider = "daytona" },
	} {
		z := x
		z.Rows = append([]Row(nil), x.Rows...)
		mutate(z.Rows)
		if validWorkloadExposure(z) {
			t.Errorf("%s: accepted", name)
		}
		if _, err := WorkloadExposureHTML(grade.WorkloadReport{}, grade.EvidenceCoverage{}, z); err == nil {
			t.Errorf("%s: the workload page rendered it", name)
		}
	}
	// NotCounted never names anything outside the table, even on a card nobody validated.
	w := x
	w.Rows = append([]Row(nil), x.Rows...)
	w.Rows[4].Scope, w.Rows[4].DeclaredProvider = "an attacker supplied scope", "an attacker supplied scope"
	if lines := w.NotCounted(); len(lines) != 1 || strings.Contains(lines[0], "attacker") ||
		!strings.HasPrefix(lines[0], "Cloud access isn't counted: Sandprobe's reviewed scope for the provider excludes") {
		t.Errorf("an unvalidated card's line: %q", lines)
	}
	w.Rows[4].Scope, w.Rows[4].DeclaredProvider = "daytona", "sprites"
	if lines := w.NotCounted(); strings.Contains(lines[0], "declared") {
		t.Errorf("a declared name that isn't the row's scope was rendered: %q", lines)
	}
}

// SCR-2, SCR-4 and PRV-17, the security re-review of 7c922f7: a workload card is unauthenticated, so every string on a
// row is accepted only as one this binary derives from that row's structure, and the page renders the derived row.
// Each mutation is refused and never rendered; the honest red, green and not-applicable rows, and a legacy one, read.
func TestWorkloadCardStringsAreDerived(t *testing.T) {
	daytona := host.Options{Mode: "exec", Excluded: host.DaytonaExclusions(), ExcludedKind: obs.SkipProviderTerms}
	honest := WorkloadExposure{Schema: "sandprobe.workload-exposure/1", InputVerification: "proof_recomputation_unauthenticated_input",
		Card: Score(replanned(t, "daytona", daytona))}
	if !validWorkloadExposure(honest) {
		t.Fatal("the honest card was refused")
	}
	var red, green int = -1, -1
	for i, r := range honest.Rows {
		if !r.Green && !r.NotApplicable && red < 0 {
			red = i
		}
		if r.Green && green < 0 {
			green = i
		}
	}
	if red < 0 || green < 0 {
		t.Fatalf("the fixture needs a red and a green row: %+v", honest.Rows)
	}
	const claim = "Sandprobe's reviewed scope for an attacker supplied scope"
	for name, mutate := range map[string]func(r []Row){
		"N/A: the reviewer's empty-scope reason": func(r []Row) { r[4].Scope, r[4].Why = "", "Not applicable: "+claim },
		"N/A: empty scope, today's reason":       func(r []Row) { r[4].Scope = "" },
		"N/A: empty scope, legacy reason, edited terms": func(r []Row) {
			r[4].Scope, r[4].Why, r[4].Terms = "", LegacyNotApplicable, claim
		},
		"N/A: empty scope, legacy reason, no terms":    func(r []Row) { r[4].Scope, r[4].Why, r[4].Terms = "", LegacyNotApplicable, "" },
		"N/A: edited reason, scope kept":               func(r []Row) { r[4].Why = "Not applicable: " + claim },
		"N/A: edited terms, scope kept":                func(r []Row) { r[4].Terms = claim },
		"N/A: another key's reason, scope kept":        func(r []Row) { r[4].Why = NotApplicableWhy("sprites", false) },
		"N/A: a declared reason":                       func(r []Row) { r[4].Why = NotApplicableWhy("daytona", true) },
		"N/A: a not-proven line":                       func(r []Row) { r[4].NotProven = "not proven: " + claim },
		"N/A: an arbitrary scope":                      func(r []Row) { r[4].Scope = "an attacker supplied scope" },
		"N/A: a declared provider":                     func(r []Row) { r[4].DeclaredProvider = "daytona" },
		"N/A: a found check":                           func(r []Row) { r[4].Found = []string{"SEC-4"} },
		"red: edited reason":                           func(r []Row) { r[red].Why = "Found: " + claim },
		"red: a reason of another structure":           func(r []Row) { r[red].Why = "Not tested" },
		"red: a not-proven line":                       func(r []Row) { r[red].NotProven = "not proven: " + claim },
		"red: terms":                                   func(r []Row) { r[red].Terms = claim },
		"red: a scope":                                 func(r []Row) { r[red].Scope = "daytona" },
		"red: a check of another category":             func(r []Row) { r[red].Found = append(r[red].Found, "PER-1") },
		"red: a check listed twice":                    func(r []Row) { r[red].Found = append(r[red].Found, r[red].Found...) },
		"green: edited not-proven line":                func(r []Row) { r[green].NotProven = "not proven: " + claim },
		"green: a reason":                              func(r []Row) { r[green].Why = claim },
		"green: an unproven check of another category": func(r []Row) { r[green].Unproven = []string{"PER-1"} },
		"any: an edited name":                          func(r []Row) { r[0].Name = claim },
		"any: an edited question":                      func(r []Row) { r[0].Question = claim },
	} {
		x := honest
		x.Rows = make([]Row, len(honest.Rows))
		for i, r := range honest.Rows {
			r.Found, r.Unknown, r.Unproven = slices.Clone(r.Found), slices.Clone(r.Unknown), slices.Clone(r.Unproven)
			x.Rows[i] = r
		}
		mutate(x.Rows)
		if validWorkloadExposure(x) {
			t.Errorf("%s: accepted", name)
		}
		if b, err := WorkloadExposureHTML(grade.WorkloadReport{}, grade.EvidenceCoverage{}, x); err == nil || strings.Contains(html.UnescapeString(string(b)), "attacker") {
			t.Errorf("%s: rendered", name)
		}
	}
	// A historical card has no coverage, so nothing but the row's own checks confines its lists to its category.
	plain := Score(replanned(t, "exec", host.Options{Mode: "exec"})) // 0.2.1 wrote no not-applicable row and no opt-in hint
	bare := honest
	bare.Card = plain
	bare.Coverage = nil
	bare.Rows = make([]Row, len(plain.Rows))
	for i, r := range plain.Rows {
		r.Coverage, r.GreenNotProven = nil, false
		r.Found, r.Unknown, r.Unproven = slices.Clone(r.Found), slices.Clone(r.Unknown), slices.Clone(r.Unproven)
		bare.Rows[i] = r
	}
	if !validWorkloadExposure(bare) {
		t.Fatal("the honest card without coverage was refused")
	}
	for name, mutate := range map[string]func(r []Row){
		"no coverage, red: a check of another category": func(r []Row) {
			r[red].Found = append(r[red].Found, "PER-1")
			r[red].Why = "Found: " + labels(Categories[red], r[red].Found)
		},
		"no coverage, red: a check listed twice": func(r []Row) {
			r[red].Found = append(r[red].Found, r[red].Found...)
			r[red].Why = "Found: " + labels(Categories[red], r[red].Found)
		},
		"no coverage, red: an unknown check": func(r []Row) {
			r[red].Unknown = []string{"NOPE-1"}
			r[red].Why = "Found: " + labels(Categories[red], r[red].Found)
		},
		"no coverage, green: an unproven check of another category": func(r []Row) {
			r[green].Unproven = []string{"PER-1"}
			r[green].NotProven = "not proven: " + labels(Categories[green], r[green].Unproven)
		},
	} {
		x := bare
		x.Rows = make([]Row, len(bare.Rows))
		for i, r := range bare.Rows {
			r.Found, r.Unknown, r.Unproven = slices.Clone(r.Found), slices.Clone(r.Unknown), slices.Clone(r.Unproven)
			x.Rows[i] = r
		}
		mutate(x.Rows)
		if validWorkloadExposure(x) {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, v := range map[string]string{"a verification label of its own": claim} {
		x := honest
		x.Verification = v
		if validWorkloadExposure(x) {
			t.Errorf("%s: accepted", name)
		}
	}
	x := honest
	x.Verification = SavedVerification
	if !validWorkloadExposure(x) {
		t.Error("the fixed saved-report label was refused")
	}
	if got := legacyScope(Categories[4], termsReasons("daytona", Categories[4].Checks)); got != "daytona" {
		t.Errorf("legacyScope: %q", got)
	}
	seen := map[string]string{} // each key's reasons pin exactly one key, so a legacy card's terms never pick two
	for _, key := range host.DeclarableProviders() {
		terms := termsReasons(key, Categories[4].Checks)
		if other, dup := seen[terms]; dup {
			t.Errorf("%s and %s share reasons", key, other)
		}
		seen[terms] = key
	}
}
