package analysis

import (
	"path/filepath"
	"slices"
	"testing"

	"sandprobe/internal/obs"
)

func TestMetadataMarkerChangesComparisonContext(t *testing.T) {
	a, b := baseline(t), baseline(t)
	a.Manifest.Marks = []obs.PlannedMark{{Root: "/data", Path: filepath.Join("/data", obs.MarkerPrefix+a.Manifest.RunID)}}
	b.Manifest.Marks = []obs.PlannedMark{{Root: "/data", Path: filepath.Join("/data", obs.LinkMarkerPrefix+b.Manifest.RunID)}}
	if !slices.Contains(Compare(a, b).ContextChanges, "declared_configuration") {
		t.Fatal("marker mechanism change hidden")
	}
	a.Manifest.Marks[0].Path = filepath.Join("/data", obs.LinkMarkerPrefix+a.Manifest.RunID)
	b.Manifest.RunID = "different-run"
	b.Manifest.Marks[0].Path = filepath.Join("/data", obs.LinkMarkerPrefix+b.Manifest.RunID)
	if slices.Contains(Compare(a, b).ContextChanges, "declared_configuration") {
		t.Fatal("different run names misclassified as a marker mechanism change")
	}
}
