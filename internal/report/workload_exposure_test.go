package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"sandprobe/internal/grade"
	"sandprobe/internal/obs"
	"sandprobe/internal/rundata"
)

func TestWorkloadExposureRecomputesBothProvidersWithoutPermissionOverrides(t *testing.T) {
	rundata.Need(t, "../../runs/aws-nitro/workload-contract-2026-11-20", "../../runs/daytona/generic-receiver-2026-11-20")
	for _, c := range []struct {
		folder string
		score  int
	}{{"aws-nitro/workload-contract-2026-11-20", 2}, {"daytona/generic-receiver-2026-11-20", 3}} {
		p := filepath.Join("..", "..", "runs", c.folder)
		raw, err := os.ReadFile(filepath.Join(p, "standard-evidence.json"))
		if err != nil {
			t.Fatal(err)
		}
		var q struct {
			Report       Doc                `json:"report"`
			Observations string             `json:"observations"`
			Evidence     obs.CanaryEvidence `json:"evidence"`
		}
		if err = json.Unmarshal(raw, &q); err != nil {
			t.Fatal(err)
		}
		x := WorkloadExposureScore(q.Report.Manifest, []byte(q.Observations), &q.Evidence)
		if x.Score != c.score || !reflect.DeepEqual(x.Card, Score(q.Report)) {
			t.Fatal("RC scoring changed", c.folder, x.Score)
		}
		bad := WorkloadExposureScore(q.Report.Manifest, []byte(`{}`), &q.Evidence)
		if bad.Valid || bad.Score != 0 {
			t.Fatal("invalid observations earned score")
		}
		var r grade.WorkloadReport
		raw, err = os.ReadFile(filepath.Join(p, "workload-report.json"))
		if err != nil || json.Unmarshal(raw, &r) != nil {
			t.Fatal("workload fixture unavailable")
		}
		var coverage grade.EvidenceCoverage
		if c.score == 2 {
			coverage = grade.WorkloadEvidenceCoverage(q.Report.Manifest, []byte(q.Observations), r)
		} else {
			raw, err = os.ReadFile(filepath.Join(p, "evidence-coverage.json"))
			if err != nil || json.Unmarshal(raw, &coverage) != nil {
				t.Fatal("coverage fixture unavailable")
			}
		}
		page, err := WorkloadExposureHTML(r, coverage, x)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(page, []byte("Exposure score:")) || !bytes.Contains(page, []byte("Unknown checks")) || !bytes.Contains(page, []byte("Not proven")) || !bytes.Contains(page, []byte("Workload configuration grade:")) {
			t.Fatal("primary or secondary evidence hidden")
		}
		x.BoxID = "unrelated"
		if _, err = WorkloadExposureHTML(r, coverage, x); err == nil {
			t.Fatal("mismatched score rendered")
		}
		if c.score == 3 {
			for _, label := range []string{"EGR-2", "EGR-5.80", "AMP-1", "image-content-binding", "host-context"} {
				if !bytes.Contains(page, []byte(label)) {
					t.Fatal("missing proof hidden", label)
				}
			}
			legacy, err := WorkloadEvidenceHTML(r, coverage)
			if err != nil {
				t.Fatal(err)
			}
			original, err := os.ReadFile(filepath.Join(p, "workload-report.html"))
			if err != nil || !bytes.Equal(legacy, original) {
				t.Fatal("historical rendering changed")
			}
		}
	}
}
