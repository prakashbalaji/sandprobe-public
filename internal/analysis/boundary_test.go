package analysis

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"sandprobe/internal/obs"
)

func analysisBoundary() *obs.BoundaryContract {
	return &obs.BoundaryContract{Schema: "sandprobe.boundary-contract/1", Workload: "aws-reference-file-v1", RequestedImage: obs.BoundaryReferenceImage,
		ReportedImageID: "containerd://sha256:" + strings.Repeat("a", 64), AgentUID: 10001, AgentGID: 10001, NetworkExpectation: "unrestricted", ResetModel: "none", ProtectedResourceAttribution: "unestablished"}
}

func TestBoundaryOfflineCompatibilityAndContext(t *testing.T) {
	a, b := loadReport(t, openReport), loadReport(t, openReport)
	old, err := Assess(a, CanaryDenyProfile)
	if err != nil || old.BoundaryContract != nil {
		t.Fatal("old context invented")
	}
	b.Manifest.BoundaryContract = analysisBoundary() // synthetic declaration; never rewrite the saved report
	raw, _ := json.Marshal(b)
	parsed, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	assessment, err := Assess(parsed, CanaryDenyProfile)
	if err != nil {
		t.Fatal(err)
	}
	if assessment.Outcome != old.Outcome || assessment.DirectTCP != old.DirectTCP || assessment.BoundaryContract.ProtectedResourceAttribution != "unestablished" {
		t.Fatal("context changed verdict or invented attribution")
	}
	parsed.Manifest.BoundaryContract.AgentUID = 0
	if assessment.BoundaryContract.AgentUID != 10001 {
		t.Fatal("assessment context aliases input")
	}
	if _, err := Assess(parsed, CanaryDenyProfile); err == nil {
		t.Fatal("bad identity accepted")
	}
	for _, pair := range [][2]*obs.BoundaryContract{{nil, analysisBoundary()}, {analysisBoundary(), nil}} {
		a.Manifest.BoundaryContract, b.Manifest.BoundaryContract = pair[0], pair[1]
		result := Compare(a, b)
		if result.NoObservedChange || !slices.Contains(result.ContextChanges, "declared_boundary_context") {
			t.Fatal("missing context silently matched")
		}
	}
	a.Manifest.BoundaryContract, b.Manifest.BoundaryContract = analysisBoundary(), analysisBoundary()
	if !Compare(a, b).NoObservedChange {
		t.Fatal("identical context mismatched")
	}
	b.Manifest.BoundaryContract.NetworkExpectation = "deny-canary-six-routes"
	if !slices.Contains(Compare(a, b).ContextChanges, "declared_boundary_context") {
		t.Fatal("policy change hidden")
	}
	// JON-1 applies inside the optional context too.
	for _, replacement := range []string{`"schema":"unknown"`, `"schema":"sandprobe.boundary-contract/1","extra":true`, `"schema":"sandprobe.boundary-contract/1","Schema":"sandprobe.boundary-contract/1"`} {
		changed := bytes.Replace(raw, []byte(`"schema":"sandprobe.boundary-contract/1"`), []byte(replacement), 1)
		if _, err := Parse(changed); err == nil {
			t.Fatal("unsupported/malformed declaration parsed")
		}
	}
}

// BND-3: invalid evidence cannot conceal a declared-context change.
func TestBoundaryInvalidComparisonContext(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		a, b := loadReport(t, openReport), loadReport(t, openReport)
		a.Grade.Valid = false
		b.Manifest.BoundaryContract = analysisBoundary()
		if reverse {
			a, b = b, a
		}
		result := Compare(a, b)
		if !result.Incomplete || result.NoObservedChange || !slices.Contains(result.ContextChanges, "declared_boundary_context") {
			t.Fatal("invalid source hid changed context")
		}
	}
}
