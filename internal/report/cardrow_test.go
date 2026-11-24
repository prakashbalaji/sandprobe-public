package report

import (
	"slices"
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
