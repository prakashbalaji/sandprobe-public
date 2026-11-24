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
}

func WorkloadExposureScore(m obs.Manifest, raw []byte, evidence *obs.CanaryEvidence) WorkloadExposure {
	r := &host.Run{Manifest: m, Doc: raw, Report: grade.GradeBytes(m, raw, evidence)}
	if evidence != nil {
		r.Evidence = *evidence
	}
	return WorkloadExposure{Schema: "sandprobe.workload-exposure/1", RunID: m.RunID, BoxID: m.BoxID, InputVerification: "proof_recomputation_unauthenticated_input", Card: Score(Build(r, Meta{}))}
}

// WorkloadExposureHTML is opt-in; historical rendering entry points keep their
// original output and no numeric score becomes a configuration/security verdict.
func WorkloadExposureHTML(r grade.WorkloadReport, coverage grade.EvidenceCoverage, exposure WorkloadExposure) ([]byte, error) {
	if !validWorkloadExposure(exposure) || exposure.RunID != r.RunID || exposure.BoxID != r.BoxID {
		return nil, errors.New("workload exposure binding mismatch")
	}
	// SCR-2, SCR-5: old v1 rows omit this display flag. Derive it only after validating their coverage, without
	// mutating the caller or treating an omitted flag as proof.
	exposure.Rows = slices.Clone(exposure.Rows)
	for i := range exposure.Rows {
		row := &exposure.Rows[i]
		row.GreenNotProven = row.Green && row.Coverage != nil && row.Coverage.Conclusive == 0
		// PRV-17: a card is unauthenticated, so the page never names a provider on its stored word: a not-applicable
		// row reads fixed text, never its stored reason or scope.
		row.Scope = ""
		if row.NotApplicable {
			row.Why = NotApplicableWhy("", false)
		}
	}
	return workloadHTML(r, &coverage, &exposure)
}

func validWorkloadExposure(x WorkloadExposure) bool {
	if x.Schema != "sandprobe.workload-exposure/1" || x.InputVerification != "proof_recomputation_unauthenticated_input" {
		return false
	}
	if !x.Valid {
		return x.Of == len(Categories) && x.Score == 0 && len(x.Rows) == 0 && x.Coverage == nil
	}
	if len(x.Rows) != len(Categories) {
		return false
	}
	green, applicable := 0, len(Categories)
	for i, row := range x.Rows {
		if row.Name != Categories[i].Name {
			return false
		}
		if !row.NotApplicable && (row.Terms != "" || row.Scope != "") || row.DeclaredProvider != "" { // PRV-17: run exec only
			return false
		}
		if row.NotApplicable { // SCR-2: never green, never found or unknown, and out of the score
			if row.Green || len(row.Found) > 0 || len(row.Unknown) > 0 {
				return false
			}
			applicable--
		}
		if !row.Green && row.GreenNotProven || x.Coverage == nil && row.GreenNotProven { // SCR-2: never on a red row, never unbacked
			return false
		}
		if row.Green {
			if len(row.Found) > 0 || len(row.Unknown) > 0 {
				return false
			}
			green++
		}
	}
	return x.Score == green && x.Of == applicable && validCardCoverage(x.Card)
}
