package report

import (
	"fmt"
	"slices"
	"strings"

	"sandprobe/internal/obs"
)

// SCR-5: coverage records what supports the score, without changing SCR-2.
// Unknown may mean an attempted check was inconclusive; it is not usable proof.
type CheckCoverage struct {
	Total         int      `json:"total"`
	UsableResults int      `json:"usable_results"`
	Conclusive    int      `json:"conclusive"`
	Complete      bool     `json:"complete"`
	Proven        []string `json:"proven,omitempty"`
	Findings      []string `json:"findings,omitempty"`
	Unproven      []string `json:"unproven,omitempty"`
	Unknown       []string `json:"unknown,omitempty"`
	ScopedOut     []string `json:"scoped_out,omitempty"`
	Skipped       []string `json:"skipped,omitempty"`
	Missing       []string `json:"missing,omitempty"`
}

type ScoreCoverage struct {
	Categories            int  `json:"categories"`
	CategoriesWithResults int  `json:"categories_with_usable_results"`
	CompleteCategories    int  `json:"complete_categories"`
	Checks                int  `json:"checks"`
	UsableResults         int  `json:"usable_results"`
	Conclusive            int  `json:"conclusive"`
	Complete              bool `json:"complete"`
}

func attachCoverage(card *Card, checks map[string]Check, unknown map[string]bool) {
	coverage := &ScoreCoverage{Categories: len(Categories)}
	for i, cat := range Categories {
		c := &CheckCoverage{Total: len(cat.Checks)}
		for _, id := range cat.Checks {
			check, exists := checks[id]
			switch {
			case unknown[id] || exists && check.Result == obs.Unknown:
				c.Unknown = append(c.Unknown, id)
			case !exists:
				c.Missing = append(c.Missing, id)
			case check.Result == obs.Skipped:
				c.Skipped = append(c.Skipped, id)
			case check.Result == obs.ScopedOut:
				c.ScopedOut = append(c.ScopedOut, id)
			case check.Result == obs.Pass || check.Result == obs.Absent:
				c.Proven = append(c.Proven, id)
			case check.Result == obs.Finding:
				c.Findings = append(c.Findings, id)
			case check.Result == obs.NotFound:
				c.Unproven = append(c.Unproven, id)
			default:
				c.Unknown = append(c.Unknown, id)
			}
		}
		c.Conclusive = len(c.Proven) + len(c.Findings)
		c.UsableResults = c.Conclusive + len(c.Unproven)
		c.Complete = c.Conclusive == c.Total
		coverage.Checks += c.Total
		coverage.UsableResults += c.UsableResults
		coverage.Conclusive += c.Conclusive
		if c.UsableResults > 0 {
			coverage.CategoriesWithResults++
		}
		if c.Complete {
			coverage.CompleteCategories++
		}
		card.Rows[i].GreenNotProven = card.Rows[i].Green && c.Conclusive == 0 // SCR-2: green with no conclusive check
		card.Rows[i].Coverage = c
	}
	coverage.Complete = coverage.CompleteCategories == coverage.Categories
	card.Coverage = coverage
}

func (c CheckCoverage) Description() string {
	s := fmt.Sprintf("Coverage: %d/%d usable results; %d/%d conclusive", c.UsableResults, c.Total, c.Conclusive, c.Total)
	for _, group := range []struct {
		label string
		ids   []string
	}{
		{"unproven", c.Unproven}, {"unknown", c.Unknown}, {"scoped out", c.ScopedOut}, {"skipped", c.Skipped}, {"missing", c.Missing},
	} {
		if len(group.ids) > 0 {
			s += "; " + group.label + ": " + strings.Join(group.ids, ", ")
		}
	}
	return s
}

func (c ScoreCoverage) Description() string {
	return fmt.Sprintf("Coverage: %d/%d categories have usable results; %d/%d categories have conclusive results for every check (%d/%d checks). Coverage is separate from the exposure score.",
		c.CategoriesWithResults, c.Categories, c.CompleteCategories, c.Categories, c.Conclusive, c.Checks)
}

// Historical cards can omit coverage; a supplied counter never invents it.
func validCardCoverage(card Card) bool {
	if card.Coverage == nil {
		for _, row := range card.Rows {
			if row.Coverage != nil {
				return false
			}
		}
		return true
	}
	if !card.Valid || len(card.Rows) != len(Categories) {
		return false
	}
	want := ScoreCoverage{Categories: len(Categories)}
	for i, row := range card.Rows {
		c := row.Coverage
		if c == nil || c.Total != len(Categories[i].Checks) || row.NotApplicable && len(c.Skipped) != c.Total {
			return false // SCR-2: a not-applicable row is one whose every check was skipped
		}
		seen := map[string]bool{}
		for _, group := range [][]string{c.Proven, c.Findings, c.Unproven, c.Unknown, c.ScopedOut, c.Skipped, c.Missing} {
			for _, id := range group {
				if seen[id] || !slices.Contains(Categories[i].Checks, id) {
					return false
				}
				seen[id] = true
			}
		}
		if len(seen) != c.Total || !slices.Equal(c.Unknown, row.Unknown) {
			return false
		}
		var unproven []string
		for _, id := range c.Unproven {
			if canRed(id) {
				unproven = append(unproven, id)
			}
		}
		if !slices.Equal(unproven, row.Unproven) {
			return false
		}
		for _, id := range row.Found {
			if !slices.Contains(c.Findings, id) {
				return false
			}
		}
		conclusive := len(c.Proven) + len(c.Findings)
		usable := conclusive + len(c.Unproven)
		if c.Conclusive != conclusive || c.UsableResults != usable || c.Complete != (conclusive == c.Total) || row.GreenNotProven && !(row.Green && conclusive == 0) {
			return false
		}
		want.Checks += c.Total
		want.Conclusive += conclusive
		want.UsableResults += usable
		if usable > 0 {
			want.CategoriesWithResults++
		}
		if c.Complete {
			want.CompleteCategories++
		}
	}
	want.Complete = want.CompleteCategories == want.Categories
	return *card.Coverage == want
}
