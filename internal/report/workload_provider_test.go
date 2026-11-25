package report

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"sandprobe/internal/grade"
	"sandprobe/internal/host"
	"sandprobe/internal/obs"
)

func TestWorkloadExposurePreservesValidatedProvider(t *testing.T) {
	raw, err := os.ReadFile("../../test/reports/bundles/egress-refused.bundle.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Manifest     obs.Manifest       `json:"manifest"`
		Observations string             `json:"observations"`
		Evidence     obs.CanaryEvidence `json:"evidence"`
	}
	if json.Unmarshal(raw, &fixture) != nil {
		t.Fatal("public bundle unreadable")
	}
	data := []byte(fixture.Observations)
	if !strings.HasPrefix(fixture.Observations, "{") {
		data, err = base64.StdEncoding.DecodeString(fixture.Observations)
		if err != nil {
			t.Fatal(err)
		}
	}
	var doc obs.Doc
	if json.Unmarshal(data, &doc) != nil || doc.Identity == nil {
		t.Fatal("public observation fixture unreadable")
	}
	m := fixture.Manifest
	if m.Skipped == nil {
		m.Skipped = map[string]string{}
	}
	m.SkipKinds = map[string]string{}
	for id, why := range host.DaytonaExclusions() {
		m.Skipped[id] = why
		m.SkipKinds[id] = obs.SkipProviderTerms
		m.Selected = slices.DeleteFunc(m.Selected, func(v string) bool { return v == id })
		doc.Observations = slices.DeleteFunc(doc.Observations, func(v obs.Observation) bool { return v.ID == id })
		delete(m.CheckNonces, id)
		delete(m.Endpoints, id)
	}
	m.WorkloadContract = &obs.WorkloadContract{Schema: "sandprobe.workload-contract/2", Profile: obs.WorkloadProfile, Provider: "daytona", IdentityMode: "host_controller_no_guest_credentials", AgentUID: 10001, AgentGID: 10001, ManagedRunID: strings.Repeat("a", 16), BoxID: m.BoxID, SnapshotID: "12345678-1234-1234-1234-123456789abc", ConfigSHA256: strings.Repeat("b", 64), IdentityPolicySHA256: strings.Repeat("c", 64), ProtectedDevice: 1, ProtectedInode: 2}
	data, _ = json.Marshal(doc)
	r := &host.Run{Manifest: m, Doc: data, Report: grade.GradeBytes(m, data, &fixture.Evidence)}
	if !r.Report.Valid {
		t.Fatalf("public fixture setup invalid: %s", r.Report.Invalid)
	}
	want := Score(Build(r, Meta{Provider: "daytona"}))
	got := WorkloadExposureScore(m, data, &fixture.Evidence)
	if !got.Valid || got.Of != 5 || got.Score != want.Score || got.Of != want.Of || *got.Coverage != *want.Coverage {
		t.Fatalf("workload score lost provider: got=%+v want=%+v", got.Card, want)
	}
	for _, row := range got.Rows {
		if row.Name == "Cloud access" && (!row.NotApplicable || row.Green || row.Coverage.Conclusive != 0) {
			t.Fatal("excluded category gained proof", row)
		}
	}
	contract := m.WorkloadContract
	m.WorkloadContract = nil
	if unqualified := WorkloadExposureScore(m, data, &fixture.Evidence); !unqualified.Valid || unqualified.Of != 6 {
		t.Fatal("undeclared provider gained native applicability", unqualified.Card)
	}
	m.WorkloadContract = contract
	m.WorkloadContract.Provider = "aws-nitro" // a v2 contract cannot assert Nitro scope.
	if bad := WorkloadExposureScore(m, data, &fixture.Evidence); bad.Valid {
		t.Fatal("invalid contract created a valid scope/score")
	}
}
