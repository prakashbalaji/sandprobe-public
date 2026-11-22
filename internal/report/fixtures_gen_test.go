package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sandprobe/internal/grade"
	"sandprobe/internal/host"
	"sandprobe/internal/obs"
)

// TestGenerateFixtureReports builds the public test reports in test/reports from the bundles the Docker fixture
// harness exported there (see test/reports/README.md): the grade comes from the grader, the page from Build, exactly as
// a run writes them. It runs only when SANDPROBE_WRITE_FIXTURES names test/reports.
func TestGenerateFixtureReports(t *testing.T) {
	dir := os.Getenv("SANDPROBE_WRITE_FIXTURES")
	if dir == "" {
		t.Skip("set SANDPROBE_WRITE_FIXTURES to test/reports to rebuild the public test reports from their bundles")
	}
	bundles, err := filepath.Glob(filepath.Join(dir, "bundles", "*.bundle.json"))
	if err != nil || len(bundles) == 0 {
		t.Fatalf("no bundles in %s/bundles: %v", dir, err)
	}
	for _, path := range bundles {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var q struct {
			Manifest     obs.Manifest       `json:"manifest"`
			Observations string             `json:"observations"`
			Evidence     obs.CanaryEvidence `json:"evidence"`
		}
		if err := json.Unmarshal(raw, &q); err != nil {
			t.Fatal(path, err)
		}
		r := &host.Run{Manifest: q.Manifest, Doc: []byte(q.Observations), Evidence: q.Evidence,
			Report: grade.GradeBytes(q.Manifest, []byte(q.Observations), &q.Evidence)}
		doc := Build(r, Meta{Version: "fixture", Provider: "docker-fixture", BoxName: q.Manifest.BoxID, CreatedBySandprobe: true,
			StartedAt: time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC), Duration: 4 * time.Second,
			Cleanup: "deleted by the fixture harness"})
		out, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		name := strings.TrimSuffix(filepath.Base(path), ".bundle.json")
		if err := os.WriteFile(filepath.Join(dir, name+".json"), append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: grade %s, valid %v, complete %v", name, doc.Grade.Letter, doc.Grade.Valid, doc.Grade.Complete)
	}
}
