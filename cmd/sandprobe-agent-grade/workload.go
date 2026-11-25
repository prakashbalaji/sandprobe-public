package main

import (
	"encoding/json"
	"errors"
	"io"

	"sandprobe/internal/grade"
	"sandprobe/internal/obs"
	"sandprobe/internal/report"
	"sandprobe/internal/strictjson"
)

type workloadSummary struct {
	EvidenceSchema   *string                  `json:"evidence_schema,omitempty"`
	Manifest         obs.Manifest             `json:"manifest"`
	Observations     string                   `json:"observations"`
	Evidence         obs.CanaryEvidence       `json:"evidence"`
	Workload         string                   `json:"workload"`
	PrivateReceiver  grade.WorkloadReceiver   `json:"private_receiver"`
	ReceiverBinding  *obs.ReceiverBinding     `json:"receiver_binding,omitempty"`
	ReceiverEvidence *obs.ReceiverCalibration `json:"receiver_evidence,omitempty"`
}

// WGR-4: private host finalization from the live collector's bound raw records.
// The exported result remains unauthenticated and conditional, not attestation.
func summarizeWorkload(in io.Reader, out io.Writer) error {
	return summarizeWorkloadEvidence(in, out, false)
}

func summarizeWorkloadEvidence(in io.Reader, out io.Writer, includeCoverage bool) error {
	var q workloadSummary
	raw, err := io.ReadAll(io.LimitReader(in, (4<<20)+1))
	if err != nil || strictjson.Decode(raw, 4<<20, &q) != nil {
		return errors.New("invalid workload summary input")
	}
	// EVD-20: accept legacy no-stage requests, never downgrade new raw evidence.
	var version string
	if q.EvidenceSchema != nil {
		version = *q.EvidenceSchema
	}
	if version != "" && version != "sandprobe.managed-evidence/1" && version != report.ManagedEvidenceSchema {
		return errors.New("unsupported managed evidence version")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return errors.New("invalid workload summary input")
	}
	if _, present := fields["evidence_schema"]; present && (q.EvidenceSchema == nil || version == "") {
		return errors.New("invalid managed evidence version")
	}
	if q.Evidence.Reset != nil && q.Evidence.Reset.FailureStage != "" && version != report.ManagedEvidenceSchema {
		return errors.New("reset diagnostic requires managed evidence version2")
	}
	r := grade.WorkloadGrade(q.Manifest, []byte(q.Observations), &q.Evidence, q.Workload)
	newReceiver := q.ReceiverBinding != nil || q.ReceiverEvidence != nil || q.Manifest.WorkloadContract != nil && q.Manifest.WorkloadContract.ReceiverBindingSHA256 != ""
	if newReceiver {
		if q.PrivateReceiver.ExpectedUID != "" || q.PrivateReceiver.ObservedUID != "" || len(q.PrivateReceiver.IssuedNonces) > 0 || len(q.PrivateReceiver.ReceivedNonces) > 0 {
			return errors.New("mixed receiver evidence modes")
		}
		var binding obs.ReceiverBinding
		var evidence obs.ReceiverCalibration
		if q.ReceiverBinding != nil {
			binding = *q.ReceiverBinding
		}
		if q.ReceiverEvidence != nil {
			evidence = *q.ReceiverEvidence
		}
		r = grade.AddReceiverCalibration(r, q.Manifest.WorkloadContract, binding, evidence)
	} else {
		r = grade.AddWorkloadReceiver(r, q.PrivateReceiver)
	}
	html, err := report.WorkloadHTML(r)
	var coverage *grade.EvidenceCoverage
	var exposure *report.WorkloadExposure
	if includeCoverage {
		v := grade.WorkloadEvidenceCoverage(q.Manifest, []byte(q.Observations), r)
		coverage = &v
		x := report.WorkloadExposureScore(q.Manifest, []byte(q.Observations), &q.Evidence)
		exposure = &x
		html, err = report.WorkloadExposureHTML(r, v, x)
	}
	if err != nil {
		return errors.New("workload report rendering failed")
	}
	return json.NewEncoder(out).Encode(struct {
		Assessment grade.WorkloadReport     `json:"assessment"`
		HTML       string                   `json:"html"`
		Coverage   *grade.EvidenceCoverage  `json:"evidence_coverage,omitempty"`
		Exposure   *report.WorkloadExposure `json:"exposure_scorecard,omitempty"`
	}{r, string(html), coverage, exposure})
}
