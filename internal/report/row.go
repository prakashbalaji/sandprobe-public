package report

import (
	"slices"
	"strings"

	"sandprobe/internal/catalog"
	"sandprobe/internal/host"
)

// outcome is one check's result as a scorecard row sees it (SCR-2). Score maps each graded check to one, and a saved
// workload card's rows are rebuilt from the outcomes its own coverage and lists allow; buildRow then makes the row
// from the outcomes alone, so both paths share every verdict and every string.
type outcome int

const (
	outMissing  outcome = iota // not in the run: says nothing either way
	outClean                   // pass, absent or scoped out
	outNotFound                // find-only check with no finding and no negative proof
	outInfo                    // a finding at Info: a completed observation, never red
	outFound                   // a finding above Info
	outUnknown                 // couldn't prove, or a result the scorecard doesn't know
	outSkipped                 // skipped with no kind the row uses
	outTerms                   // skipped under the row's PRV-row scope (provider_terms, as this binary's policy derives)
	outOptIn                   // skipped under PRV-15's or RCP-4's opt-in default
)

// buildRow is SCR-2's row for a category from its checks' outcomes: the one place a verdict and its text are decided.
// scope is the PRV-row key a not-applicable row names, declared says the operator declared it (PRV-17), and noCanary is
// HCN-5's choice. A row is not applicable only when no check was tested and every check of the category is outTerms.
func buildRow(cat Category, out map[string]outcome, scope string, declared, noCanary bool) Row {
	r, tested := Row{Name: cat.Name, Question: cat.Question}, 0
	var terms, optIn []string
	for _, id := range cat.Checks {
		switch out[id] {
		case outUnknown:
			tested++
			r.Unknown = append(r.Unknown, id)
		case outTerms:
			terms = append(terms, id)
		case outOptIn:
			optIn = append(optIn, id)
		case outClean, outInfo:
			tested++
		case outNotFound:
			tested++
			if canRed(id) {
				r.Unproven = append(r.Unproven, id)
			}
		case outFound:
			tested++
			r.Found = append(r.Found, id)
		}
	}
	switch {
	case len(r.Found) > 0:
		r.Why = "Found: " + labels(cat, r.Found)
		if len(r.Unknown) > 0 {
			r.Why += "; couldn't prove: " + labels(cat, r.Unknown)
		}
	case len(r.Unknown) > 0 && noCanary && allNeedCanary(r.Unknown):
		r.Why = "Not tested: run without a canary" // SCR-2, HCN-5: the host's own choice, never a box string
	case len(r.Unknown) > 0:
		r.Why = "Couldn't prove: " + labels(cat, r.Unknown)
	case tested == 0 && len(terms) == len(cat.Checks) && host.DeclaredExclusions(scope) != nil: // SCR-2: out of the score
		r.NotApplicable, r.Why, r.Terms, r.Scope = true, NotApplicableWhy(scope, declared), termsReasons(scope, terms), scope
		if declared {
			r.DeclaredProvider = scope
		}
	case tested == 0 && len(optIn) > 0: // SCR-2: PRV-15's or RCP-4's default, which the person may lift
		r.Why = "Not tested: opt in with -provider-endpoints " + strings.Join(optIn, ",") + " if your provider's terms allow"
	case tested == 0:
		r.Why = "Not tested"
	default:
		r.Green = true
		if len(r.Unproven) > 0 {
			r.NotProven = "not proven: " + labels(cat, r.Unproven)
		}
	}
	return r
}

// cardRow rebuilds row i of an unauthenticated workload card (SCR-4) from the least the card can't forge against
// itself: the category, this binary's PRV-row table, and the row's own check lists and coverage. It checks the lists'
// invariants first, then tries every outcome map they allow, builds each row with buildRow, and accepts the stored
// row only when it equals one of them as a whole. It returns that built row, which is what the page renders.
func cardRow(i int, row Row) (Row, bool) {
	cat := Categories[i]
	if !rowInvariants(cat, row) {
		return Row{}, false
	}
	key := ""
	if row.NotApplicable {
		key = row.Scope
		if key == "" { // a 0.3.0 card names no scope: its terms must pin exactly one key
			key = legacyScope(cat, row.Terms)
		}
	}
	for _, out := range cardOutcomes(cat, row, key) {
		for _, noCanary := range []bool{false, true} {
			want := buildRow(cat, out, key, false, noCanary)
			want.Coverage = row.Coverage
			if row.Coverage != nil {
				want.GreenNotProven = want.Green && row.Coverage.Conclusive == 0 // SCR-2: derived, never supplied
			}
			if sameRow(row, want) {
				return want, true
			}
		}
	}
	return Row{}, false
}

// rowInvariants are the cross-checks a card's lists must pass before any row is built (SCR-2, SCR-5): each list holds
// only the category's own checks, once each, in catalog order; found, unknown and unproven are disjoint; a found check
// can be found above Info, and an unproven one is find-only; a not-applicable row lists nothing and its coverage
// records no finding; a green row has no found or unknown check; every coverage finding a row doesn't list as found
// is a check with an Info variant; and a card without coverage (0.2.1's form) carries no not-applicable row, scope,
// terms or declared provider, since 0.2.1 wrote none.
func rowInvariants(cat Category, row Row) bool {
	for _, ids := range [][]string{row.Found, row.Unknown, row.Unproven} {
		if !inCategory(cat, ids) {
			return false
		}
	}
	for _, id := range row.Found {
		if slices.Contains(row.Unknown, id) || slices.Contains(row.Unproven, id) || !canRed(id) {
			return false
		}
	}
	for _, id := range row.Unproven {
		if ck, _ := catalog.Get(id); slices.Contains(row.Unknown, id) || ck == nil || ck.Kind != catalog.FindOnly {
			return false
		}
	}
	if row.NotApplicable && (len(row.Found)+len(row.Unknown)+len(row.Unproven) > 0 || row.Coverage == nil || len(row.Coverage.Findings) > 0) {
		return false
	}
	if row.Green && len(row.Found)+len(row.Unknown) > 0 {
		return false
	}
	if c := row.Coverage; c != nil {
		for _, id := range c.Findings {
			if !slices.Contains(row.Found, id) && !hasInfo(id) {
				return false
			}
		}
		for _, id := range c.Unproven {
			if ck, _ := catalog.Get(id); ck == nil || ck.Kind != catalog.FindOnly {
				return false
			}
		}
	} else if row.NotApplicable || row.Terms != "" || row.Scope != "" || row.GreenNotProven {
		return false
	}
	return row.DeclaredProvider == "" // PRV-17: the managed workload runners never declare a provider
}

// cardOutcomes is every outcome map row's evidence allows. With coverage, each check's outcome is its coverage group's;
// a finding is outInfo only when its check has an Info variant and the row doesn't list it, else outFound; a skipped check may be outSkipped, outOptIn when it is a
// provider endpoint, or outTerms when key's PRV-row entry excludes it. Without coverage (0.2.1's form), the row's own
// lists fix theirs, and the rest are all clean or all missing: the two forms that change the row.
func cardOutcomes(cat Category, row Row, key string) []map[string]outcome {
	base := map[string]outcome{}
	var open []string // skipped checks whose kind the card doesn't record
	if c := row.Coverage; c != nil {
		for _, g := range []struct {
			ids []string
			o   outcome
		}{{c.Proven, outClean}, {c.ScopedOut, outClean}, {c.Unproven, outNotFound}, {c.Unknown, outUnknown}, {c.Missing, outMissing}} {
			for _, id := range g.ids {
				base[id] = g.o
			}
		}
		for _, id := range c.Findings { // Info only for a check that has an Info variant: never a green on the card's word
			base[id] = outFound
			if hasInfo(id) && !slices.Contains(row.Found, id) {
				base[id] = outInfo
			}
		}
		open = c.Skipped
	} else {
		for _, id := range row.Found {
			base[id] = outFound
		}
		for _, id := range row.Unknown {
			base[id] = outUnknown
		}
		for _, id := range row.Unproven {
			base[id] = outNotFound
		}
		var maps []map[string]outcome
		for _, rest := range []outcome{outClean, outMissing} {
			m := map[string]outcome{}
			for _, id := range cat.Checks {
				if o, ok := base[id]; ok {
					m[id] = o
				} else {
					m[id] = rest
				}
			}
			maps = append(maps, m)
		}
		return maps
	}
	entry := host.DeclaredExclusions(key)
	maps := []map[string]outcome{base}
	for _, id := range open {
		options := []outcome{outSkipped}
		if catalog.ProviderEndpoints[id] {
			options = append(options, outOptIn)
		}
		if _, ok := entry[id]; ok {
			options = append(options, outTerms)
		}
		var next []map[string]outcome
		for _, m := range maps {
			for _, o := range options {
				n := make(map[string]outcome, len(m)+1)
				for k, v := range m {
					n[k] = v
				}
				n[id] = o
				next = append(next, n)
			}
		}
		maps = next
	}
	return maps
}

// sameRow is the stored row equal to the built one as a whole, nil and empty lists alike. A stored green-not-proven flag
// may be omitted (0.3.0's cards had none) but never supplied against the built one, and a 0.3.0 not-applicable row
// carries no scope and 0.3.0's own reason where the built row carries today's.
func sameRow(stored, want Row) bool {
	if want.NotApplicable && stored.Scope == "" {
		want.Scope, want.Why = "", LegacyNotApplicable
	}
	if !want.GreenNotProven {
		if stored.GreenNotProven {
			return false
		}
	} else {
		stored.GreenNotProven = true
	}
	return stored.Name == want.Name && stored.Question == want.Question && stored.Green == want.Green &&
		stored.GreenNotProven == want.GreenNotProven && stored.NotApplicable == want.NotApplicable &&
		stored.Why == want.Why && stored.Terms == want.Terms && stored.Scope == want.Scope &&
		stored.DeclaredProvider == want.DeclaredProvider && stored.NotProven == want.NotProven &&
		slices.Equal(stored.Found, want.Found) && slices.Equal(stored.Unknown, want.Unknown) &&
		slices.Equal(stored.Unproven, want.Unproven) && stored.Coverage == want.Coverage
}

// hasInfo says a check has an Info variant, so a finding on it may be a completed observation that never turns a row
// red (SEC-3 and EGR-4 today).
func hasInfo(id string) bool {
	ck, ok := catalog.Get(id)
	if !ok {
		return false
	}
	for _, v := range ck.Variants {
		if v.Severity == catalog.Info {
			return true
		}
	}
	return false
}
