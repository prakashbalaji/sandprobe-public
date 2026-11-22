package analysis

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"sandprobe/internal/catalog"
	"sandprobe/internal/obs"
	"sandprobe/internal/report"
)

// demo is a public report from the demo's hardened Docker box: the generic baseline these tests change.
const demo = "../../demo/reports/hardened.json"

func baseline(t *testing.T) *report.Doc {
	t.Helper()
	d, e := Load(demo)
	if e != nil {
		t.Fatal(e)
	}
	return d
}
func TestRunCorpus(t *testing.T) {
	count, roots, least := 0, []string{"../../demo/reports", "../../test/reports"}, 6
	var err error
	for _, root := range roots {
		err = errors.Join(err, filepath.WalkDir(root, func(path string, e os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if e.IsDir() || filepath.Ext(path) != ".json" {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			var tag struct {
				Schema string `json:"schema"`
			}
			_ = json.Unmarshal(b, &tag)
			if tag.Schema != "sandprobe/1" {
				return nil
			}
			if _, err := Parse(b); err != nil {
				t.Errorf("corpus rejected %s", path)
			}
			count++
			return nil
		}))
	}
	if err != nil {
		t.Fatal(err)
	}
	if count < least {
		t.Fatalf("missing corpus: %d reports", count)
	}
}
func TestProfileAndCompare(t *testing.T) {
	a := baseline(t)
	b := baseline(t)
	if len(Summarize(a).Areas) != 5 {
		t.Fatal("missing areas")
	}
	c := Compare(a, b)
	if !c.NoObservedChange || c.Incomplete {
		t.Fatal("identical reports differ")
	}
	// Different run IDs/times/nonces do not change observations.
	b.Run.ID = "new"
	b.Manifest.RunID = "new"
	b.Run.Nonce = "n-new"
	b.Manifest.Nonce = "n-new"
	if !Compare(a, b).NoObservedChange {
		t.Fatal("ephemeral IDs compared")
	}
	for i := range b.Checks {
		if b.Checks[i].ID == "SEC-1" {
			b.Checks[i].Result = obs.Unknown
		}
	}
	c = Compare(a, b)
	if len(c.CoverageLoss) == 0 || c.NoObservedChange {
		t.Fatal("coverage loss hidden")
	}
	b = baseline(t)
	b.Identity.UID++
	if len(Compare(a, b).ContextChanges) == 0 {
		t.Fatal("identity change hidden")
	}
}

func TestComparisonFlagsChangedRecordedReferenceContext(t *testing.T) {
	a, b := baseline(t), baseline(t)
	a.Grade.Notes = append(a.Grade.Notes, "REF-3: requested image A; Kubernetes-reported image ID A")
	b.Grade.Notes = append(b.Grade.Notes, "REF-3: requested image B; Kubernetes-reported image ID B")
	c := Compare(a, b)
	if c.NoObservedChange || len(c.ContextChanges) != 1 || c.ContextChanges[0] != "reported_reference_context" {
		t.Fatal("changed recorded reference configuration hidden")
	}
}

func TestComparisonDoesNotTreatOutcomeNotesAsConfiguration(t *testing.T) {
	a, b := baseline(t), baseline(t)
	a.Grade.Notes = []string{"REF-2: same reference settings", "REF-3: same profile and image"}
	b.Grade.Notes = []string{"CHN-2: a root-equivalent amplifier", "REF-2: same reference settings", "REF-3: same profile and image", "lifecycle error: cleanup failed"}
	if c := Compare(a, b); !c.NoObservedChange || len(c.ContextChanges) != 0 {
		t.Fatal("outcome notes changed configuration")
	}
}
func TestContradictions(t *testing.T) {
	for _, edit := range []func(*report.Doc){
		func(d *report.Doc) { d.Checks = append(d.Checks, d.Checks[0]) },
		func(d *report.Doc) { d.Grade.Counts["critical"]++ },
		func(d *report.Doc) { d.Manifest.BoxID = "other" },
		func(d *report.Doc) { d.Manifest.ProbeSHA256 = "other" },
		func(d *report.Doc) {
			d.Manifest.Selected = nil
			d.Manifest.Skipped = nil
			d.Checks = nil
			d.Findings = nil
			d.Grade.Counts = map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
		},
		func(d *report.Doc) { d.Grade.Unknown = []string{"SEC-1"} },
		func(d *report.Doc) { d.Manifest.Selected = append(d.Manifest.Selected, "UNKNOWN") },
		func(d *report.Doc) { d.Checks[0].Result = "pass"; d.Checks[0].Proof = nil },
	} {
		d := baseline(t)
		edit(d)
		if Validate(d) == nil {
			t.Fatal("contradiction accepted")
		}
	}
}
func TestFileRefusal(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "link")
	if err := os.Symlink(demo, link); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{link, dir, "/dev/null"} {
		if _, err := Load(p); err == nil {
			t.Fatal("unsafe input accepted")
		}
	}
}

func TestCanaryProofAndUnknownIdentity(t *testing.T) {
	d := baseline(t)
	for i := range d.Checks {
		if d.Checks[i].ID == "EGR-2" {
			d.Checks[i].Result = obs.Pass
			d.Checks[i].Proof.Mechanism = ""
		}
	}
	if Validate(d) == nil {
		t.Fatal("empty canary mechanism accepted")
	}
	a, b := baseline(t), baseline(t)
	a.Identity = nil
	b.Identity = nil
	c := Compare(a, b)
	if !c.Incomplete || c.NoObservedChange {
		t.Fatal("missing identity treated as known context")
	}
}

// New catalog entries need an explicit reviewed profile classification.
func TestExplicitAreaCoverage(t *testing.T) {
	for _, check := range catalog.Checks {
		if area(check.ID) == "" {
			t.Errorf("unmapped catalog check %s", check.ID)
		}
	}
	for _, id := range []string{"AMP-8", "AMP-8.future", "SEC-new", "EGR-new", "PER-new", "NEW-1"} {
		if area(id) != "" {
			t.Errorf("unclassified check %s received a default area", id)
		}
	}
	d := baseline(t)
	original := catalog.Checks
	catalog.Checks = append(append([]catalog.Check(nil), original...), catalog.Check{ID: "NEW-1"})
	defer func() { catalog.Checks = original }()
	if Validate(d) == nil {
		t.Fatal("unmapped catalog accepted")
	}
}
