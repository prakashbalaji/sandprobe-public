package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"sandprobe/internal/grade"
)

func TestWorkloadSummaryRejectsAmbiguousRecordsAndLabelsSuppliedInput(t *testing.T) {
	for _, input := range []string{`{`, `{"workload":"reported_passed","workload":"reported_failed"}`, `{"unknown":true}`, `{"exposure_scorecard":{"valid":true,"score":6,"of":6}}`} {
		var out bytes.Buffer
		if err := summarizeWorkload(strings.NewReader(input), &out); err == nil || out.Len() != 0 {
			t.Fatal("ambiguous records accepted")
		}
	}
	var out bytes.Buffer
	if err := summarizeWorkload(strings.NewReader(`{}`), &out); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Assessment grade.WorkloadReport `json:"assessment"`
		HTML       string               `json:"html"`
	}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Assessment.ConfigurationGrade != "" || result.Assessment.BenchmarkRequirementsMet || result.Assessment.InputVerification != "retrospective_recomputation_unauthenticated_input" {
		t.Fatal("unbound records earned grade", out.String())
	}
	if !strings.Contains(result.HTML, grade.ConfigurationAssurance) {
		t.Fatal("HTML lost assurance limit")
	}
	// Ordinary live mode requires the frozen pre-workload contract.
	out.Reset()
	if run(context.Background(), strings.NewReader(`{"pod":{},"canary_state":"/nonexistent"}`), &out) == nil || out.Len() != 0 {
		t.Fatal("live grading accepted missing contract")
	}
}

func TestWorkloadSummaryRejectsMixedReceiverModes(t *testing.T) {
	var out bytes.Buffer
	in := `{"receiver_binding":{},"private_receiver":{"expected_uid":"legacy"}}`
	if err := summarizeWorkload(strings.NewReader(in), &out); err == nil || out.Len() != 0 {
		t.Fatal("mixed receiver evidence accepted")
	}
}

func TestWorkloadSummaryEvidenceVersion(t *testing.T) {
	for _, input := range []string{`{"evidence_schema":null}`, `{"evidence_schema":""}`, `{"evidence_schema":"future"}`, `{"evidence":{"Reset":{"FailureStage":"create_replacement"}}}`, `{"evidence_schema":"sandprobe.managed-evidence/1","evidence":{"Reset":{"FailureStage":"create_replacement"}}}`} {
		var out bytes.Buffer
		if summarizeWorkload(strings.NewReader(input), &out) == nil || out.Len() != 0 {
			t.Fatal("incompatible raw evidence graded", input)
		}
	}
	for _, input := range []string{`{}`, `{"evidence_schema":"sandprobe.managed-evidence/1"}`, `{"evidence_schema":"sandprobe.managed-evidence/2","evidence":{"Reset":{"FailureStage":"create_replacement"}}}`} {
		var out bytes.Buffer
		if err := summarizeWorkload(strings.NewReader(input), &out); err != nil {
			t.Fatal(err)
		}
		var result struct {
			Assessment grade.WorkloadReport `json:"assessment"`
		}
		if json.Unmarshal(out.Bytes(), &result) != nil || result.Assessment.BenchmarkRequirementsMet || result.Assessment.ConfigurationGrade != "" {
			t.Fatal("format version earned security credit")
		}
	}
}
