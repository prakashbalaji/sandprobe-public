package report

import (
	"testing"

	"sandprobe/internal/obs"
)

func TestHostControllerNeedsReportVersionThree(t *testing.T) {
	for _, schema := range []string{"sandprobe.workload-contract/1", "sandprobe.workload-contract/2", "sandprobe.workload-contract/3"} {
		m := obs.Manifest{WorkloadContract: &obs.WorkloadContract{Schema: schema}}
		want := Schema
		if schema == "sandprobe.workload-contract/3" {
			want = SchemaHostController
		}
		if SchemaFor(m) != want {
			t.Fatal("contract semantics were emitted under the wrong report version")
		}
	}
}
