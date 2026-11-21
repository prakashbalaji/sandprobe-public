package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"sandprobe/internal/grade"
	"sandprobe/internal/host"
	"sandprobe/internal/obs"
	"sandprobe/internal/report"
	"sandprobe/internal/rundata"
)

// WGR-6: replay a scanned historical collection, never a new cloud/model run.
// Literal wire keys intentionally mirror the Python collector, not Go field
// names: a formatter/serializer change must migrate its consumer explicitly.
func TestReportCompatibilityPreservesCollectorAndWorkloadGrade(t *testing.T) {
	rundata.Need(t, "../../runs/aws-nitro/workload-contract-2026-11-20/standard-evidence.json")
	path := filepath.Join("..", "..", "runs", "aws-nitro", "workload-contract-2026-11-20", "standard-evidence.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Report       report.Doc         `json:"report"`
		Observations string             `json:"observations"`
		Evidence     obs.CanaryEvidence `json:"evidence"`
		Input        obs.Input          `json:"input"`
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Report.Manifest.WorkloadContract == nil {
		t.Fatal("fixture lost frozen workload contract")
	}
	run := &host.Run{Manifest: fixture.Report.Manifest, Doc: []byte(fixture.Observations), Evidence: fixture.Evidence,
		Report: grade.GradeBytes(fixture.Report.Manifest, []byte(fixture.Observations), &fixture.Evidence)}
	doc := report.Build(run, report.Meta{Version: fixture.Report.Probe.Version, Provider: "aws-nitro", BoxName: fixture.Report.Run.Box.Name,
		CreatedBySandprobe: true, StartedAt: time.Unix(0, 0), Cleanup: "pending"})
	if _, err = report.HTML(doc, "dark"); err != nil {
		t.Fatal("legacy formatter no longer renders", err)
	}
	wire, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	legacy := compatObject(t, wire)
	compatEqual(t, legacy, "schema", "sandprobe/1")
	runWire := compatObject(t, legacy["run"])
	compatEqual(t, runWire, "provider", "aws-nitro")
	compatEqual(t, runWire, "id", fixture.Report.Manifest.RunID)
	box := compatObject(t, runWire["box"])
	compatEqual(t, box, "provider_id", fixture.Report.Manifest.BoxID)
	generic := compatObject(t, legacy["grade"])
	compatEqual(t, generic, "letter", "F")
	compatEqual(t, generic, "valid", true)
	compatEqual(t, generic, "complete", true)
	manifest := compatObject(t, legacy["manifest"])
	compatEqual(t, manifest, "RunID", fixture.Report.Manifest.RunID)
	compatEqual(t, manifest, "BoxID", fixture.Report.Manifest.BoxID)
	compatEqual(t, manifest, "ProbeSHA256", fixture.Report.Manifest.ProbeSHA256)
	var contract obs.WorkloadContract
	if err = json.Unmarshal(manifest["workload_contract"], &contract); err != nil {
		t.Fatal("collector lost workload_contract", err)
	}
	if !reflect.DeepEqual(contract, *fixture.Report.Manifest.WorkloadContract) {
		t.Fatal("formatter changed frozen contract")
	}
	// Receiver values below are synthetic calibration controls, not a claim about
	// historical receiver receipts. No missing delivery is called a refusal proof.
	request := map[string]any{"manifest": json.RawMessage(legacy["manifest"]), "observations": fixture.Observations,
		"evidence": fixture.Evidence, "workload": "reported_passed", "private_receiver": grade.WorkloadReceiver{
			ExpectedUID: "report-compatibility-fixture", ObservedUID: "report-compatibility-fixture",
			IssuedNonces: []string{compatNonce('1'), compatNonce('2'), compatNonce('3')}, ReceivedNonces: []string{compatNonce('1'), compatNonce('3')}}}
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err = summarizeWorkload(bytes.NewReader(payload), &output); err != nil {
		t.Fatal("collector/finalizer wire contract broke", err)
	}
	response := compatObject(t, output.Bytes())
	assessment := compatObject(t, response["assessment"])
	for key, want := range map[string]any{"schema": "sandprobe.workload-assessment/1", "profile": "networked-coding-v1",
		"configuration_grade": "B", "legacy_generic_grade": "F", "security_assurance": grade.ConfigurationAssurance,
		"measurement_assumption": "honest_host_shipped_unattested_probe", "input_verification": "retrospective_recomputation_unauthenticated_input",
		"box_id": fixture.Report.Manifest.BoxID, "run_id": fixture.Report.Manifest.RunID, "workload": "reported_passed",
		"valid": true, "complete": true, "contract_bound": true, "benchmark_requirements_met": true} {
		compatEqual(t, assessment, key, want)
	}
	var unknown []string
	if err = json.Unmarshal(assessment["unknown"], &unknown); err != nil || len(unknown) != 0 {
		t.Fatal("fixture acquired missing evidence", err, unknown)
	}
	var html string
	if err = json.Unmarshal(response["html"], &html); err != nil || html == "" {
		t.Fatal("primary report HTML no longer supplied", err)
	}
	// No assertions about HTML layout, colors, ordering or incidental wording.
}

func compatObject(t *testing.T, raw []byte) map[string]json.RawMessage {
	t.Helper()
	var value map[string]json.RawMessage
	if err := json.Unmarshal(raw, &value); err != nil || value == nil {
		t.Fatal("expected collector JSON object", err)
	}
	return value
}
func compatEqual(t *testing.T, value map[string]json.RawMessage, key string, want any) {
	t.Helper()
	raw, ok := value[key]
	if !ok {
		t.Fatalf("collector-required field %q removed/renamed; migrate consumer/schema explicitly", key)
	}
	var got any
	if err := json.Unmarshal(raw, &got); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("collector-required field %q changed: got %v, want %v (%v)", key, got, want, err)
	}
}
func compatNonce(char byte) string { return string(bytes.Repeat([]byte{char}, 48)) }
