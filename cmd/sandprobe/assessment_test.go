package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sandprobe/internal/analysis"
	"sandprobe/internal/obs"
)

// Real runs of local Docker boxes that differ only in a firewall (test/reports/README.md).
const assessOpen = "../../test/reports/egress-open.json"
const assessRefused = "../../test/reports/egress-refused.json"

func TestAssessmentCLI(t *testing.T) {
	for _, tc := range []struct {
		args     []string
		exit     int
		contains string
	}{
		{[]string{"assess", assessOpen, analysis.CanaryDenyProfile, "-o", "json"}, 6, `"reported_delivery": 6`},
		{[]string{"assess", assessRefused, analysis.CanaryDenyProfile, "-o", "json"}, 5, `"reported_refusal": 4`},
		{[]string{"assess", assessRefused, analysis.CanaryDenyProfile}, 5, `Highest-severity finding IDs ["AMP-2"] (unverified).`},
		{[]string{"assess", assessRefused, "custom", "-o", "json"}, 2, "usage"},
		{[]string{"assess", assessRefused, "-o", "json"}, 2, "usage"},
		{[]string{"assess", "/dev/null", analysis.CanaryDenyProfile, "-o", "json"}, 2, "report.input"},
	} {
		var out, stderr bytes.Buffer
		code := run(tc.args, &out, &stderr)
		if code != tc.exit || !strings.Contains(out.String()+stderr.String(), tc.contains) {
			t.Fatalf("args %v: code %d, output %s", tc.args, code, out.String()+stderr.String())
		}
	}
}

func TestAssessmentCLIPartialKeepsViolationAndEscapesSource(t *testing.T) {
	d, err := analysis.Load(assessOpen)
	if err != nil {
		t.Fatal(err)
	}
	d.Run.Provider = "test\x1b[2J\nFORGED"
	// A source failure outside the six routes must still prevent complete exit6.
	for i := range d.Checks {
		if d.Checks[i].ID == "SEC-1" {
			d.Checks[i].Result = obs.Unknown
			d.Checks[i].Severity = ""
			d.Checks[i].EvidenceClass = ""
			d.Checks[i].Proof = nil
		}
	}
	d.Grade.Unknown = []string{"SEC-1"}
	d.Grade.Complete = false
	// SEC-1 is a pass in the fixture, so no finding/count removal is needed.
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "partial.json")
	if err = os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"text", "json"} {
		var out, stderr bytes.Buffer
		code := run([]string{"assess", path, analysis.CanaryDenyProfile, "-o", format}, &out, &stderr)
		if code != 5 || !strings.Contains(out.String(), "reported_violation") || strings.ContainsRune(out.String(), '\x1b') {
			t.Fatalf("partial violation/escaping lost: exit %d, %s", code, stderr.String())
		}
	}
}
