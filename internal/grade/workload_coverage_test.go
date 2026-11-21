package grade

import (
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"sandprobe/internal/catalog"
	"sandprobe/internal/obs"
	"sandprobe/internal/rundata"
)

func TestEvidenceCategoriesCoverCatalogExactlyOnce(t *testing.T) {
	counts := map[string]int{}
	for _, c := range evidenceCategories {
		for _, id := range c.checks {
			counts[id]++
		}
	}
	if len(evidenceCategories) != 6 {
		t.Fatal("published categories changed")
	}
	for _, id := range catalog.IDs() {
		if counts[id] != 1 {
			t.Fatalf("%s belongs to %d categories", id, counts[id])
		}
	}
}

func TestCoverageGroupsRetainedDaytonaUnknownsWithoutRegrading(t *testing.T) {
	rundata.Need(t, "../../runs/daytona/workload-followup-2026-11-20/")
	var bundle struct {
		Report struct {
			Manifest obs.Manifest `json:"manifest"`
		} `json:"report"`
		Raw      string             `json:"observations"`
		Evidence obs.CanaryEvidence `json:"evidence"`
	}
	root := "../../runs/daytona/workload-followup-2026-11-20/"
	b, err := os.ReadFile(root + "standard-evidence.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &bundle); err != nil {
		t.Fatal(err)
	}
	r := AddWorkloadReceiver(WorkloadGrade(bundle.Report.Manifest, []byte(bundle.Raw), &bundle.Evidence, "reported_passed"), WorkloadReceiver{})
	var expected WorkloadReport
	b, err = os.ReadFile(root + "workload-report.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &expected); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r, expected) {
		t.Fatal("retained assessment changed")
	}
	v := WorkloadEvidenceCoverage(bundle.Report.Manifest, []byte(bundle.Raw), r)
	if !v.Valid || v.UnknownControls != 8 || len(v.Gaps) != 4 {
		t.Fatalf("wrong grouped coverage: %+v", v)
	}
	want := map[string]int{"image-content-evidence": 1, "private-process-context": 4, "network-proof": 2, "final-receiver-collection": 1}
	seen := map[string]bool{}
	for _, g := range v.Gaps {
		if len(g.Controls) != want[g.ID] {
			t.Fatalf("wrong gap: %+v", g)
		}
		for _, id := range g.Controls {
			if seen[id] || !slices.Contains(r.Unknown, id) {
				t.Fatal("invented/duplicate unknown", id)
			}
			seen[id] = true
		}
	}
	if len(seen) != 8 {
		t.Fatal("unknown evidence disappeared")
	}
	accounted := len(v.Context)
	for _, c := range v.Categories {
		accounted += len(c.Controls)
	}
	if accounted != len(r.Controls) {
		t.Fatal("control lost from coverage view")
	}
	for _, a := range v.Exchanges {
		ck, ok := catalog.Get(a.Check)
		if !ok || ck.Canary == nil || ck.Canary.Proto != "tcp" {
			t.Fatal("DNS/UDP shown as a TCP exchange")
		}
	}
}

func TestExchangeDiagnosticsCannotChangeNetworkGrade(t *testing.T) {
	m, d, c := workloadCase()
	o := observation(d, "EGR-2")
	o.Attempts[0].Outcome = "connected"
	raw, _ := json.Marshal(d)
	expected := GradeBytes(m, raw, c)
	if expected.Letter != "C" {
		t.Fatal("connected without receipt must stay unknown")
	}
	for _, diagnostic := range [][2]string{{"exchange", "completed"}, {"tls_handshake", "pin_mismatch"}, {"read_reply", "timeout"}, {"read_reply", "http_status_403"}, {"read_reply", "http_status_407"}, {"read_reply", "http_other_status"}, {"tls_handshake", "connection_reset"}, {"send_marker", "broken_pipe"}, {"tls_handshake", "non_tls_reply"}, {"untrusted-stage", "untrusted-secret-error"}} {
		o.Attempts[0].ExchangeStage = diagnostic[0]
		o.Attempts[0].ExchangeResult = diagnostic[1]
		raw, _ = json.Marshal(d)
		if got := GradeBytes(m, raw, c); !reflect.DeepEqual(got, expected) {
			t.Fatal("diagnostic changed grade")
		}
		v := WorkloadEvidenceCoverage(m, raw, runWorkload(m, d, c, "reported_passed"))
		wire, _ := json.Marshal(v)
		if strings.Contains(string(wire), "untrusted-secret") || strings.Contains(string(wire), "untrusted-stage") {
			t.Fatal("unbounded guest diagnostic rendered")
		}
	}
}

func TestInvalidAssessmentDoesNotEarnCoveragePass(t *testing.T) {
	v := WorkloadEvidenceCoverage(obs.Manifest{}, nil, WorkloadGrade(obs.Manifest{}, nil, nil, "reported_passed"))
	if v.Valid || len(v.Gaps) != 1 || len(v.Context) != 0 {
		t.Fatal("invalid assessment acquired conformance")
	}
}

func TestCoverageRejectsUnknownAndUnselectedDiagnosticChecks(t *testing.T) {
	m, d, c := workloadCase()
	r := runWorkload(m, d, c, "reported_passed")
	d.Observations = append(d.Observations, obs.Observation{ID: "EGR-synthetic-sensitive-label", Attempts: []obs.Attempt{{Outcome: "connected", ExchangeStage: "exchange", ExchangeResult: "completed"}}})
	m.Selected = append(m.Selected, "EGR-synthetic-sensitive-label")
	m.Selected = slices.DeleteFunc(m.Selected, func(id string) bool { return id == "EGR-2" })
	raw, _ := json.Marshal(d)
	v := WorkloadEvidenceCoverage(m, raw, r)
	for _, a := range v.Exchanges {
		if a.Check == "EGR-2" || a.Check == "EGR-synthetic-sensitive-label" {
			t.Fatal("unknown/unselected check rendered")
		}
	}
	wire, _ := json.Marshal(v)
	if strings.Contains(string(wire), "synthetic-sensitive") {
		t.Fatal("arbitrary guest check label escaped")
	}
}

func TestCoverageExchangeRowsRequireValidatedRunBinding(t *testing.T) {
	m, d, c := workloadCase()
	r := runWorkload(m, d, c, "reported_passed")
	raw, _ := json.Marshal(d)
	if len(WorkloadEvidenceCoverage(m, raw, r).Exchanges) == 0 {
		t.Fatal("missing valid TCP diagnostics")
	}
	d.RunID = "wrong-run"
	raw, _ = json.Marshal(d)
	if len(WorkloadEvidenceCoverage(m, raw, r).Exchanges) != 0 {
		t.Fatal("unrelated guest observations shown as bound diagnostics")
	}
	d.RunID = m.RunID
	r.Valid = false
	raw, _ = json.Marshal(d)
	if len(WorkloadEvidenceCoverage(m, raw, r).Exchanges) != 0 {
		t.Fatal("invalid assessment acquired diagnostics")
	}
}
