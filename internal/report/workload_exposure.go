package report

import (
	"errors"

	"sandprobe/internal/grade"
	"sandprobe/internal/host"
	"sandprobe/internal/obs"
	"slices"
)

// WorkloadExposure retains SCR-4's RC score independently of workload permission
// overrides. Saved inputs remain unauthenticated, even when proofs recompute.
type WorkloadExposure struct {
	Schema            string `json:"schema"`
	RunID             string `json:"run_id"`
	BoxID             string `json:"box_id"`
	InputVerification string `json:"input_verification"`
	Card
	// gradedInfo is severity evidence only this binary's own grading gives, in the same process (SCR-7): the checks
	// whose finding it graded Info. It is never serialized, so a card read from a file never carries it, and a finding
	// on a check with both Info and higher variants (SEC-3) that the row doesn't list fails closed on such a card.
	gradedInfo map[string]bool
}

func WorkloadExposureScore(m obs.Manifest, raw []byte, evidence *obs.CanaryEvidence) WorkloadExposure {
	r := &host.Run{Manifest: m, Doc: raw, Report: grade.GradeBytes(m, raw, evidence)}
	if evidence != nil {
		r.Evidence = *evidence
	}
	return exposureFromDoc(Build(r, Meta{}))
}

// exposureFromDoc is the workload card for a report this process just graded, with the severity evidence its own
// grading gives (SCR-7).
func exposureFromDoc(d Doc) WorkloadExposure {
	info := map[string]bool{}
	for _, c := range d.Checks {
		if c.Result == obs.Finding && c.Severity == "info" {
			info[c.ID] = true
		}
	}
	return WorkloadExposure{Schema: "sandprobe.workload-exposure/1", RunID: d.Manifest.RunID, BoxID: d.Manifest.BoxID,
		InputVerification: "proof_recomputation_unauthenticated_input", Card: Score(d), gradedInfo: info}
}

// WorkloadExposureHTML is opt-in; historical rendering entry points keep their
// original output and no numeric score becomes a configuration/security verdict.
// The card is unauthenticated input (SCR-4): it is accepted only when every string on every row is one this binary
// derives from that row's structure and its own fixed tables, and the page then renders the derived rows, never the
// card's stored text (SCR-2, PRV-17).
func WorkloadExposureHTML(r grade.WorkloadReport, coverage grade.EvidenceCoverage, exposure WorkloadExposure) ([]byte, error) {
	if !validWorkloadExposure(exposure) || exposure.RunID != r.RunID || exposure.BoxID != r.BoxID {
		return nil, errors.New("workload exposure binding mismatch")
	}
	rows := make([]Row, len(exposure.Rows))
	for i, row := range exposure.Rows {
		rows[i], _ = cardRow(i, row, exposure.gradedInfo) // the built row, green-not-proven flag included; never the stored text
	}
	exposure.Rows = rows
	return workloadHTML(r, &coverage, &exposure)
}

// LegacyNotApplicable is the not-applicable reason 0.3.0 wrote (SCR-2), the only historical form a saved card's
// not-applicable row may carry; a card carrying it is rendered in today's wording, never in its own.
const LegacyNotApplicable = "Not applicable: this box holds no cloud identity of yours that Sandprobe checks here; the provider's own endpoints weren't tested (their terms)"

// inCategory says the ids are the category's own checks, each once, in catalog order, as Score lists them.
func inCategory(cat Category, ids []string) bool {
	last := -1
	for _, id := range ids {
		at := slices.Index(cat.Checks, id)
		if at <= last {
			return false
		}
		last = at
	}
	return true
}

// legacyScope is the one PRV-row key whose reasons for the category's checks equal terms, or "" when none or more
// than one does, so a legacy card's terms never pick a name the table can't pin down.
func legacyScope(cat Category, terms string) string {
	var found []string
	for _, key := range host.DeclarableProviders() {
		if termsReasons(key, cat.Checks) == terms {
			found = append(found, key)
		}
	}
	if len(found) != 1 {
		return ""
	}
	return found[0]
}

func validWorkloadExposure(x WorkloadExposure) bool {
	if x.Schema != "sandprobe.workload-exposure/1" || x.InputVerification != "proof_recomputation_unauthenticated_input" ||
		x.Verification != "" && x.Verification != SavedVerification {
		return false
	}
	if !x.Valid {
		return x.Of == len(Categories) && x.Score == 0 && len(x.Rows) == 0 && x.Coverage == nil
	}
	if len(x.Rows) != len(Categories) {
		return false
	}
	// SCR-7: validate first, build second. The coverage partition (every ID the category's own, each once, every list
	// bounded by the category's size) is checked before any row is built, so a forged list costs only a linear pass.
	if !validCardCoverage(x.Card) {
		return false
	}
	green, applicable := 0, len(Categories)
	for i, row := range x.Rows {
		built, ok := cardRow(i, row, x.gradedInfo) // the stored row must equal a row buildRow makes from its own evidence (SCR-2)
		if !ok {
			return false
		}
		if built.NotApplicable { // the card's totals come from the built rows, never its own counts
			applicable--
		}
		if built.Green {
			green++
		}
	}
	return x.Score == green && x.Of == applicable
}
