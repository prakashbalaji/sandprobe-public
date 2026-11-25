package report

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"sandprobe/internal/catalog"
	"sandprobe/internal/grade"
	"sandprobe/internal/host"
	"sandprobe/internal/obs"
)

// cloneCard deep-copies a card's rows, lists and coverage, so a mutation never reaches the card it came from.
func cloneCard(c Card) Card {
	out := c
	if c.Coverage != nil {
		v := *c.Coverage
		out.Coverage = &v
	}
	out.Rows = make([]Row, len(c.Rows))
	for i, r := range c.Rows {
		r.Found, r.Unknown, r.Unproven = slices.Clone(r.Found), slices.Clone(r.Unknown), slices.Clone(r.Unproven)
		if r.Coverage != nil {
			v := *r.Coverage
			v.Proven, v.Findings, v.Unproven = slices.Clone(v.Proven), slices.Clone(v.Findings), slices.Clone(v.Unproven)
			v.Unknown, v.ScopedOut, v.Skipped, v.Missing = slices.Clone(v.Unknown), slices.Clone(v.ScopedOut), slices.Clone(v.Skipped), slices.Clone(v.Missing)
			r.Coverage = &v
		}
		out.Rows[i] = r
	}
	return out
}

// recount makes a mutated card's counters agree with its lists and rows again (score, of, every coverage counter), so a
// mutation is refused only for the structure it changes, never for a stale count.
func recount(c *Card) {
	c.Score, c.Of = 0, len(Categories)
	for _, r := range c.Rows {
		if r.Green {
			c.Score++
		}
		if r.NotApplicable {
			c.Of--
		}
	}
	if c.Coverage == nil {
		return
	}
	total := ScoreCoverage{Categories: len(Categories)}
	for _, r := range c.Rows {
		v := r.Coverage
		v.Conclusive = len(v.Proven) + len(v.Findings)
		v.UsableResults = v.Conclusive + len(v.Unproven)
		v.Complete = v.Conclusive == v.Total
		total.Checks += v.Total
		total.Conclusive += v.Conclusive
		total.UsableResults += v.UsableResults
		if v.UsableResults > 0 {
			total.CategoriesWithResults++
		}
		if v.Complete {
			total.CompleteCategories++
		}
	}
	total.Complete = total.CompleteCategories == total.Categories
	*c.Coverage = total
}

// asCard wraps c as a workload exposure card.
func asCard(c Card) WorkloadExposure {
	return WorkloadExposure{Schema: "sandprobe.workload-exposure/1", InputVerification: "proof_recomputation_unauthenticated_input", Card: c}
}

// excludesAll says a provider's PRV-row entry excludes every check of a category: the only case SCR-2 makes it N/A.
func excludesAll(provider string, cat Category) bool {
	entry := host.DeclaredExclusions(provider)
	for _, id := range cat.Checks {
		if _, ok := entry[id]; !ok {
			return false
		}
	}
	return true
}

// SCR-2, SCR-4 and the security review's round 3: for every provider in the table and every category, a card claiming
// the category not applicable, in today's form and in 0.3.0's, with coverage that records every check skipped, is
// accepted only where the provider's entry excludes every check of the category, exactly Score's condition. Without
// coverage (0.2.1's form, which had no not-applicable row) it is always refused.
func TestCardNotApplicableOnlyWhereTheTableExcludesEveryCheck(t *testing.T) {
	accepted := 0
	for _, provider := range host.DeclarableProviders() {
		honest := Score(replanned(t, provider, host.Options{Mode: "exec", Excluded: host.DeclaredExclusions(provider), ExcludedKind: obs.SkipProviderTerms}))
		if !validWorkloadExposure(asCard(honest)) {
			t.Fatalf("%s: the honest card was refused", provider)
		}
		for i, cat := range Categories {
			for _, form := range []string{"today's", "0.3.0's", "without coverage"} {
				c := cloneCard(honest)
				r := &c.Rows[i]
				*r = Row{Name: cat.Name, Question: cat.Question, NotApplicable: true, Why: NotApplicableWhy(provider, false),
					Terms: termsReasons(provider, cat.Checks), Scope: provider, Coverage: &CheckCoverage{Total: len(cat.Checks), Skipped: slices.Clone(cat.Checks)}}
				if form == "0.3.0's" {
					r.Scope, r.Why = "", LegacyNotApplicable
				}
				recount(&c)
				if form == "without coverage" {
					c.Coverage = nil
					for j := range c.Rows {
						c.Rows[j].Coverage, c.Rows[j].GreenNotProven = nil, false
					}
				}
				want := form != "without coverage" && excludesAll(provider, cat)
				if got := validWorkloadExposure(asCard(c)); got != want {
					t.Errorf("%s, %s, %s form: accepted %v, want %v", provider, cat.Name, form, got, want)
				}
				if _, err := WorkloadExposureHTML(grade.WorkloadReport{}, grade.EvidenceCoverage{}, asCard(c)); (err == nil) != want {
					t.Errorf("%s, %s, %s form: rendered %v, want %v", provider, cat.Name, form, err == nil, want)
				}
				if want {
					accepted++
				}
			}
		}
	}
	if accepted == 0 {
		t.Fatal("no (provider, category) pair was accepted: the loop proves nothing")
	}
}

// SCR-2 and SCR-5, sandprobe-codex's two reproductions of 279502a and one mutation per invariant: each is refused and
// never rendered. A legitimate Info finding beside a green row is accepted, so the finding invariant refuses no honest
// card.
func TestCardRowInvariants(t *testing.T) {
	daytona := host.Options{Mode: "exec", Excluded: host.DaytonaExclusions(), ExcludedKind: obs.SkipProviderTerms}
	honest := Score(replanned(t, "daytona", daytona))
	if !validWorkloadExposure(asCard(honest)) {
		t.Fatal("the honest card was refused")
	}
	stripped := func(c *Card) {
		c.Coverage = nil
		for j := range c.Rows {
			c.Rows[j].Coverage, c.Rows[j].GreenNotProven = nil, false
		}
	}
	// a green row with a proven check that has no Info variant, for codex's second reproduction
	green, provenID := -1, ""
	for i, r := range honest.Rows {
		if r.Green && r.Coverage != nil {
			for _, id := range r.Coverage.Proven {
				if !hasInfo(id) && green < 0 {
					green, provenID = i, id
				}
			}
		}
	}
	red := slices.IndexFunc(honest.Rows, func(r Row) bool { return len(r.Found) > 0 })
	if green < 0 || red < 0 {
		t.Fatalf("the fixture needs a proven green row and a found row: %+v", honest.Rows)
	}
	twoSided := ""
	for _, id := range Categories[green].Checks {
		if ck, _ := catalog.Get(id); ck.Kind == catalog.TwoSided {
			twoSided = id
		}
	}
	for name, mutate := range map[string]func(c *Card){
		"codex 1: N/A row with an unproven check, coverage omitted": func(c *Card) { stripped(c); c.Rows[4].Unproven = []string{"SEC-4"} },
		"codex 1: N/A row with an unproven check, coverage kept":    func(c *Card) { c.Rows[4].Unproven = []string{"SEC-4"} },
		"codex 2: green row whose coverage records a finding it doesn't list": func(c *Card) {
			v := c.Rows[green].Coverage
			v.Proven = slices.DeleteFunc(v.Proven, func(id string) bool { return id == provenID })
			v.Findings = append(v.Findings, provenID)
			slices.SortFunc(v.Findings, func(a, b string) int {
				return slices.Index(Categories[green].Checks, a) - slices.Index(Categories[green].Checks, b)
			})
			recount(c)
		},
		"found and unknown share a check":  func(c *Card) { c.Rows[red].Unknown = append(c.Rows[red].Unknown, c.Rows[red].Found[0]) },
		"found and unproven share a check": func(c *Card) { c.Rows[red].Unproven = append(c.Rows[red].Unproven, c.Rows[red].Found[0]) },
		"N/A row with a found check":       func(c *Card) { c.Rows[4].Found = []string{"SEC-4"} },
		"N/A row with an unknown check":    func(c *Card) { c.Rows[4].Unknown = []string{"SEC-4"} },
		"N/A row whose coverage records a finding": func(c *Card) {
			v := c.Rows[4].Coverage
			v.Skipped, v.Findings = []string{"AMP-7"}, []string{"SEC-4"}
			recount(c)
		},
		"green row with a found check":    func(c *Card) { c.Rows[green].Found = []string{provenID} },
		"green row with an unknown check": func(c *Card) { c.Rows[green].Unknown = []string{provenID} },
		"unproven holds a two-sided check": func(c *Card) {
			c.Rows[green].Unproven = []string{twoSided}
			c.Rows[green].NotProven = "not proven: " + labels(Categories[green], c.Rows[green].Unproven)
		},
		"found holds a check that is only ever Info": func(c *Card) {
			c.Rows[1].Found = []string{"EGR-4"}
			c.Rows[1].Why = "Found: " + labels(Categories[1], c.Rows[1].Found)
		},
		"coverage unproven holds a two-sided check": func(c *Card) {
			v := c.Rows[green].Coverage
			v.Proven = slices.DeleteFunc(v.Proven, func(id string) bool { return id == twoSided })
			v.Unproven = append(v.Unproven, twoSided)
			recount(c)
		},
		"no coverage, a scope":             func(c *Card) { stripped(c); c.Rows[0].Scope = "daytona" },
		"no coverage, terms":               func(c *Card) { stripped(c); c.Rows[0].Terms = "Daytona scope excludes metadata (PRV-12)" },
		"no coverage, green not proven":    func(c *Card) { stripped(c); c.Rows[green].GreenNotProven = true },
		"a declared provider":              func(c *Card) { c.Rows[0].DeclaredProvider = "daytona" },
		"score edited":                     func(c *Card) { c.Score++ },
		"of edited":                        func(c *Card) { c.Of-- },
		"green not proven on a proven row": func(c *Card) { c.Rows[green].GreenNotProven = true },
		"red row turned green":             func(c *Card) { c.Rows[red].Green, c.Rows[red].Why = true, ""; recount(c) },
		"green row turned red":             func(c *Card) { c.Rows[green].Green, c.Rows[green].Why = false, "Not tested"; recount(c) },
	} {
		c := cloneCard(honest)
		mutate(&c)
		if validWorkloadExposure(asCard(c)) {
			t.Errorf("%s: accepted", name)
		}
		if _, err := WorkloadExposureHTML(grade.WorkloadReport{}, grade.EvidenceCoverage{}, asCard(c)); err == nil {
			t.Errorf("%s: rendered", name)
		}
	}
	// A legitimate Info finding: Exfiltration's EGR-4 recorded as a finding the row doesn't list stays a green row.
	c := cloneCard(honest)
	if !c.Rows[1].Green || c.Rows[1].Coverage == nil {
		t.Fatalf("the fixture's Exfiltration row: %+v", c.Rows[1])
	}
	v := c.Rows[1].Coverage
	for _, g := range []*[]string{&v.Proven, &v.Unproven, &v.Unknown, &v.ScopedOut, &v.Skipped, &v.Missing} {
		*g = slices.DeleteFunc(*g, func(id string) bool { return id == "EGR-4" })
	}
	v.Findings = append(v.Findings, "EGR-4")
	slices.SortFunc(v.Findings, func(a, b string) int {
		return slices.Index(Categories[1].Checks, a) - slices.Index(Categories[1].Checks, b)
	})
	c.Rows[1].Unproven = slices.DeleteFunc(c.Rows[1].Unproven, func(id string) bool { return id == "EGR-4" })
	if len(c.Rows[1].Unproven) > 0 {
		c.Rows[1].NotProven = "not proven: " + labels(Categories[1], c.Rows[1].Unproven)
	} else {
		c.Rows[1].NotProven = ""
	}
	recount(&c)
	if !validWorkloadExposure(asCard(c)) {
		t.Errorf("a legitimate Info finding on a green row was refused: %+v", c.Rows[1])
	}
}

// sec3Card is a graded report where SEC-3 has a finding at severity and every other check a legal clean result, as
// the workload card this process builds from it, with its own grading's severity evidence (SCR-7).
func sec3Card(severity string) WorkloadExposure {
	d := legalNotFound()
	for i := range d.Checks {
		if d.Checks[i].ID == "SEC-3" {
			d.Checks[i].Result, d.Checks[i].Severity = obs.Finding, severity
		}
	}
	return exposureFromDoc(d)
}

// fromFile is x as a card read back from a file: JSON keeps every field but the in-process severity evidence.
func fromFile(t *testing.T, x WorkloadExposure) WorkloadExposure {
	t.Helper()
	b, err := json.Marshal(x)
	if err != nil {
		t.Fatal(err)
	}
	var y WorkloadExposure
	if err := json.Unmarshal(b, &y); err != nil {
		t.Fatal(err)
	}
	return y
}

// SCR-7, sandprobe-codex's final finding on #67: SEC-3 has both Info and High variants, so a SEC-3 finding a row doesn't
// list is Info only on this process's own grading. A genuine High SEC-3 card recast as green with one coordinated edit
// (found and why cleared, green set, score up, coverage unchanged) is refused, in process and read from a file. An
// honest Info SEC-3 card reads green in process and fails closed read from a file, which carries no severity
// evidence; an Info-only check (EGR-4) needs none.
func TestCardSEC3SeverityFailsClosed(t *testing.T) {
	high := sec3Card("high")
	if !validWorkloadExposure(high) || high.Rows[0].Green || !slices.Contains(high.Rows[0].Found, "SEC-3") {
		t.Fatalf("the honest High SEC-3 card: valid %v, %+v", validWorkloadExposure(high), high.Rows[0])
	}
	recast := func(x WorkloadExposure) WorkloadExposure {
		x.Card = cloneCard(x.Card)
		r := &x.Rows[0]
		r.Found, r.Why, r.Green = nil, "", true
		x.Score++
		return x
	}
	for name, x := range map[string]WorkloadExposure{"in process": recast(high), "read from a file": recast(fromFile(t, high))} {
		if validWorkloadExposure(x) {
			t.Errorf("codex's recast High SEC-3 card, %s: accepted", name)
		}
		if _, err := WorkloadExposureHTML(grade.WorkloadReport{}, grade.EvidenceCoverage{}, x); err == nil {
			t.Errorf("codex's recast High SEC-3 card, %s: rendered", name)
		}
	}
	info := sec3Card("info")
	if !validWorkloadExposure(info) || !info.Rows[0].Green || !slices.Contains(info.Rows[0].Coverage.Findings, "SEC-3") {
		t.Fatalf("the honest Info SEC-3 card in process: valid %v, %+v", validWorkloadExposure(info), info.Rows[0])
	}
	if _, err := WorkloadExposureHTML(grade.WorkloadReport{}, grade.EvidenceCoverage{}, info); err != nil {
		t.Errorf("the honest Info SEC-3 card in process didn't render: %v", err)
	}
	if saved := fromFile(t, info); validWorkloadExposure(saved) {
		t.Error("an Info SEC-3 card read from a file, with no severity evidence, was accepted")
	}
	egr4 := legalNotFound()
	for i := range egr4.Checks {
		if egr4.Checks[i].ID == "EGR-4" {
			egr4.Checks[i].Result, egr4.Checks[i].Severity = obs.Finding, "info"
		}
	}
	if x := fromFile(t, exposureFromDoc(egr4)); !validWorkloadExposure(x) || !x.Rows[1].Green {
		t.Errorf("an Info-only EGR-4 finding read from a file was refused: %+v", x.Rows[1])
	}
}

// honestRow is an oracle written apart from the validator: what any accepted row must satisfy for the page to show no
// false pass, from its coverage and the card's severity evidence alone (SCR-2, SCR-5, SCR-7).
func honestRow(cat Category, r Row, gradedInfo map[string]bool) string {
	c := r.Coverage
	if c == nil {
		return ""
	}
	for _, id := range c.Findings {
		infoByEvidence := hasInfo(id) && (!canRed(id) || gradedInfo[id])
		if !infoByEvidence && !slices.Contains(r.Found, id) {
			return "a finding that may be above Info isn't listed as found"
		}
	}
	for _, id := range r.Found {
		if !slices.Contains(c.Findings, id) {
			return "a found check coverage doesn't record as a finding"
		}
	}
	tested := len(c.Proven) + len(c.Findings) + len(c.Unproven) + len(c.ScopedOut) + len(c.Unknown)
	switch {
	case r.Green && (len(r.Found) > 0 || len(c.Unknown) > 0 || tested == 0 || r.Why != ""):
		return "a green row with a finding, an unknown, no tested check, or a reason"
	case r.NotApplicable:
		entry := host.DeclaredExclusions(r.Scope)
		if r.Scope == "" {
			entry = host.DeclaredExclusions(legacyScope(cat, r.Terms))
		}
		for _, id := range cat.Checks {
			if _, ok := entry[id]; !ok || !slices.Contains(c.Skipped, id) {
				return "a not-applicable row whose provider doesn't exclude, or the card doesn't skip, every check"
			}
		}
	case !r.Green && len(r.Found) > 0 && !strings.HasPrefix(r.Why, "Found: "):
		return "a red row with findings whose reason doesn't say found"
	}
	return ""
}

// SCR-7: coordinated mutations, pairs and triples across found, why, green, not-proven, coverage and the card's
// totals, on honest cards of every form. Every card the validator accepts satisfies honestRow on every row and has
// totals equal to its rows; codex's recast is one of the combinations.
func TestCardCoordinatedMutations(t *testing.T) {
	daytona := host.Options{Mode: "exec", Excluded: host.DaytonaExclusions(), ExcludedKind: obs.SkipProviderTerms}
	legacy := asCard(Score(replanned(t, "daytona", daytona)))
	legacy.Card = cloneCard(legacy.Card)
	legacy.Rows[4].Scope, legacy.Rows[4].Why = "", LegacyNotApplicable
	fixtures := map[string]WorkloadExposure{
		"High SEC-3 in process":       sec3Card("high"),
		"High SEC-3 from a file":      fromFile(t, sec3Card("high")),
		"Info SEC-3 in process":       sec3Card("info"),
		"native Daytona":              asCard(Score(replanned(t, "daytona", daytona))),
		"run exec opt-in":             asCard(Score(replanned(t, "exec", host.Options{Mode: "exec", Excluded: host.ExecExclusions(), ExcludedKind: obs.SkipOptIn, Existing: true}))),
		"run exec without a canary":   asCard(Score(replanned(t, "exec", host.Options{Mode: "exec", Excluded: host.ExecExclusions(), ExcludedKind: obs.SkipOptIn, Existing: true, NoCanary: true}))),
		"0.3.0 legacy not applicable": legacy,
	}
	tried, accepted := 0, 0
	for fname, f := range fixtures {
		if !validWorkloadExposure(f) {
			t.Fatalf("%s: the honest card was refused", fname)
		}
		for i, cat := range Categories {
			base := f.Rows[i]
			if base.Coverage == nil {
				continue
			}
			var founds [][]string // as is, cleared, and one finding added or removed
			founds = append(founds, base.Found, nil)
			for _, id := range append(slices.Clone(base.Coverage.Findings), base.Coverage.Proven...) {
				if slices.Contains(base.Found, id) {
					founds = append(founds, slices.DeleteFunc(slices.Clone(base.Found), func(s string) bool { return s == id }))
				} else {
					n := append(slices.Clone(base.Found), id)
					slices.SortFunc(n, func(a, b string) int { return slices.Index(cat.Checks, a) - slices.Index(cat.Checks, b) })
					founds = append(founds, n)
				}
			}
			moves := []string{""} // as is, or one check moved between proven and findings
			moves = append(moves, base.Coverage.Proven...)
			moves = append(moves, base.Coverage.Findings...)
			for _, found := range founds {
				whys := []string{base.Why, "", "Not tested"}
				if len(found) > 0 {
					whys = append(whys, "Found: "+labels(cat, found))
				}
				for _, why := range whys {
					for _, green := range []bool{base.Green, !base.Green} {
						for _, notProven := range []string{base.NotProven, ""} {
							for _, move := range moves {
								for _, recounted := range []bool{true, false} {
									x := f
									x.Card = cloneCard(f.Card)
									r := &x.Rows[i]
									r.Found, r.Why, r.Green, r.NotProven = slices.Clone(found), why, green, notProven
									if !green {
										r.GreenNotProven = false
									}
									if move != "" {
										v := r.Coverage
										order := func(a, b string) int { return slices.Index(cat.Checks, a) - slices.Index(cat.Checks, b) }
										if slices.Contains(v.Proven, move) {
											v.Proven = slices.DeleteFunc(v.Proven, func(s string) bool { return s == move })
											v.Findings = append(v.Findings, move)
											slices.SortFunc(v.Findings, order)
										} else {
											v.Findings = slices.DeleteFunc(v.Findings, func(s string) bool { return s == move })
											v.Proven = append(v.Proven, move)
											slices.SortFunc(v.Proven, order)
										}
									}
									if recounted {
										recount(&x.Card)
									}
									tried++
									cardBuilds.Store(0)
									ok := validWorkloadExposure(x)
									if n := cardBuilds.Load(); n > int64(2*cardOutcomeCeiling*len(Categories)) {
										t.Fatalf("%s: one card cost %d builds, over the ceiling", fname, n)
									}
									if !ok {
										continue
									}
									accepted++
									green, applicable := 0, len(Categories)
									for j, row := range x.Rows {
										if why := honestRow(Categories[j], row, x.gradedInfo); why != "" {
											t.Errorf("%s, row %s: accepted %s: %+v", fname, row.Name, why, row)
										}
										if row.Green {
											green++
										}
										if row.NotApplicable {
											applicable--
										}
									}
									if x.Score != green || x.Of != applicable {
										t.Errorf("%s: accepted totals %d/%d against rows %d/%d", fname, x.Score, x.Of, green, applicable)
									}
								}
							}
						}
					}
				}
			}
		}
	}
	t.Logf("tried %d coordinated mutations; %d accepted, every one honest by the oracle", tried, accepted)
	if tried < 10000 {
		t.Fatalf("only %d mutations: the enumeration shrank", tried)
	}
}

// SCR-7, security-agent's review of 0ceb1d3: work on an unauthenticated card is bounded before it is validated. A card
// is refused with no row built when its coverage repeats a check (the reviewer's 10 and 20 repeated SEC-4 skips under
// Modal, and 10,000), or any coverage group or row list is longer than its category; a card that passes the partition
// costs at most 6 builds per row, counted, never timed.
func TestCardWorkIsBounded(t *testing.T) {
	ceiling := int64(2 * cardOutcomeCeiling * len(Categories))
	modal := asCard(Score(replanned(t, "modal", host.Options{Mode: "exec", Excluded: host.ModalExcluded, ExcludedKind: obs.SkipProviderTerms})))
	if !validWorkloadExposure(modal) || !modal.Rows[4].NotApplicable {
		t.Fatalf("the honest Modal card: %+v", modal.Rows[4])
	}
	check := func(name string, x WorkloadExposure, maxBuilds int64) {
		t.Helper()
		cardBuilds.Store(0)
		if validWorkloadExposure(x) {
			t.Errorf("%s: accepted", name)
		}
		if n := cardBuilds.Load(); n > maxBuilds {
			t.Errorf("%s: %d rows built, want at most %d", name, n, maxBuilds)
		}
	}
	repeat := func(id string, n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = id
		}
		return out
	}
	for _, n := range []int{10, 20, 10000} {
		x := modal
		x.Card = cloneCard(modal.Card)
		x.Rows[4].Coverage.Skipped = repeat("SEC-4", n)
		check(fmt.Sprintf("%d repeated SEC-4 skips", n), x, 0)
	}
	for g := 0; g < 7; g++ {
		x := modal
		x.Card = cloneCard(modal.Card)
		v := x.Rows[1].Coverage
		groups := []*[]string{&v.Proven, &v.Findings, &v.Unproven, &v.Unknown, &v.ScopedOut, &v.Skipped, &v.Missing}
		*groups[g] = append(*groups[g], repeat(Categories[1].Checks[0], 10000)...)
		check(fmt.Sprintf("coverage group %d oversized", g), x, 0)
	}
	for _, list := range []string{"found", "unknown", "unproven"} {
		x := modal
		x.Card = cloneCard(modal.Card)
		r := &x.Rows[1]
		big := repeat(Categories[1].Checks[0], 10000)
		switch list {
		case "found":
			r.Found = big
		case "unknown":
			r.Unknown = big
		case "unproven":
			r.Unproven = big
		}
		check("row "+list+" oversized, with coverage", x, 0)
		y := x
		y.Card = cloneCard(x.Card)
		y.Coverage = nil
		for j := range y.Rows {
			y.Rows[j].Coverage, y.Rows[j].GreenNotProven = nil, false
		}
		check("row "+list+" oversized, without coverage", y, ceiling)
	}
	x := asCard(Score(replanned(t, "exec", host.Options{Mode: "exec", Excluded: host.ExecExclusions(), ExcludedKind: obs.SkipOptIn, Existing: true})))
	x.Card = cloneCard(x.Card)
	x.Rows[4].Why = "Not tested: opt in with -provider-endpoints " + strings.Repeat("SEC-4,", 10000) + "AMP-7 if your provider's terms allow"
	check("an opt-in reason naming 10,000 checks", x, ceiling)
	if ids, ok := optInNamed(Categories[4], x.Rows[4].Why); ok || len(ids) > 0 {
		t.Errorf("optInNamed read %d checks from an oversized reason", len(ids))
	}
	for name, f := range map[string]WorkloadExposure{"modal": modal, "exec opt-in": asCard(Score(replanned(t, "exec", host.Options{Mode: "exec", Excluded: host.ExecExclusions(), ExcludedKind: obs.SkipOptIn, Existing: true})))} {
		for i, r := range f.Rows {
			if n := len(cardOutcomes(Categories[i], r, r.Scope, nil)); n > cardOutcomeCeiling {
				t.Errorf("%s row %s: %d outcome maps, ceiling %d", name, r.Name, n, cardOutcomeCeiling)
			}
		}
	}
}
