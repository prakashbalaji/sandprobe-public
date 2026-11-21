package report

import (
	"errors"
	"sandprobe/internal/grade"
	"sandprobe/internal/host"
	"sandprobe/internal/obs"
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
	return workloadHTML(r, &coverage, &exposure)
}

func validWorkloadExposure(x WorkloadExposure) bool {
	if x.Schema != "sandprobe.workload-exposure/1" || x.InputVerification != "proof_recomputation_unauthenticated_input" || x.Of != len(Categories) {
		return false
	}
	if !x.Valid {
		return x.Score == 0 && len(x.Rows) == 0
	}
	if len(x.Rows) != len(Categories) {
		return false
	}
	green := 0
	for i, row := range x.Rows {
		if row.Name != Categories[i].Name {
			return false
		}
		if row.Green {
			if len(row.Found) > 0 || len(row.Unknown) > 0 {
				return false
			}
			green++
		}
	}
	return x.Score == green
}
