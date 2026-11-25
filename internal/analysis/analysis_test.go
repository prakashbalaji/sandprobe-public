package analysis

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"sandprobe/internal/catalog"
	"sandprobe/internal/host"
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

func TestFrozenUploadEndpointSavedConsistency(t *testing.T) {
	d := baseline(t)
	if _, skipped := d.Manifest.Skipped["EGR-6"]; skipped {
		d.Manifest.Selected = append(d.Manifest.Selected, "EGR-6")
	}
	delete(d.Manifest.Skipped, "EGR-6")
	delete(d.Manifest.SkipKinds, "EGR-6")
	for i := range d.Checks {
		if d.Checks[i].ID == "EGR-6" {
			d.Checks[i].Result = obs.NotFound
			d.Checks[i].Reason = ""
		}
	}
	d.Manifest.Targets["EGR-6"] = []string{"github.com=1.1.1.1"}
	if err := Validate(d); err != nil {
		t.Fatal("valid bound-target export rejected", err)
	}
	d.Manifest.Targets["EGR-6"] = []string{"github.com=169.254.169.254"}
	if err := Validate(d); err == nil {
		t.Fatal("saved export accepted infrastructure target")
	}
}

// CMP-2: what got better, what is only no longer found, and each report's score. None of it touches CMP-1's lists.
func TestCompareBetter(t *testing.T) {
	set := func(d *report.Doc, id, result, severity string) {
		for i := range d.Checks {
			if d.Checks[i].ID == id {
				d.Checks[i].Result, d.Checks[i].Severity = result, severity
			}
		}
	}
	for _, tc := range []struct {
		before, beforeSev, after, afterSev      string
		better, applies, notProven, loss, worse bool
	}{
		{obs.Finding, "high", obs.Pass, "", true, false, false, false, false},
		{obs.Finding, "high", obs.Absent, "", true, false, false, false, false},
		{obs.Finding, "info", obs.Pass, "", true, false, false, false, false},
		{obs.Unknown, "", obs.Pass, "", true, false, false, false, false},
		{obs.Finding, "high", obs.ScopedOut, "", false, true, false, false, false},
		{obs.Unknown, "", obs.ScopedOut, "", false, true, false, false, false},
		{obs.Finding, "high", obs.NotFound, "", false, false, true, false, false},
		{obs.Finding, "high", obs.Unknown, "", false, false, true, true, false},
		{obs.Unknown, "", obs.NotFound, "", false, false, false, false, false},
		{obs.Finding, "high", obs.Finding, "low", false, false, false, false, false},
		{obs.Pass, "", obs.Pass, "", false, false, false, false, false},
		{obs.Pass, "", obs.ScopedOut, "", false, false, false, false, false},
		{obs.Pass, "", obs.Finding, "high", false, false, false, false, true},
	} {
		a, b := baseline(t), baseline(t)
		set(a, "SEC-2", tc.before, tc.beforeSev)
		set(b, "SEC-2", tc.after, tc.afterSev)
		c := Compare(a, b)
		has := func(ids []string) bool { return len(ids) == 1 && ids[0] == "SEC-2" }
		if has(c.GotBetter) != tc.better || has(c.NoLongerApplies) != tc.applies || has(c.NotProven) != tc.notProven ||
			has(c.CoverageLoss) != tc.loss || has(c.NewOrWorse) != tc.worse {
			t.Errorf("%s/%s to %s/%s: better %q, no longer applies %q, not proven %q, loss %q, worse %q", tc.before, tc.beforeSev,
				tc.after, tc.afterSev, c.GotBetter, c.NoLongerApplies, c.NotProven, c.CoverageLoss, c.NewOrWorse)
		}
		if len(c.GotBetter)+len(c.NoLongerApplies)+len(c.NotProven) > 1 {
			t.Errorf("%s to %s: a check listed twice", tc.before, tc.after)
		}
	}

	// Better never hides worse: the same pair with one check better and another worse keeps both.
	a, b := baseline(t), baseline(t)
	set(a, "PER-1", obs.Finding, "low")
	set(b, "SEC-3", obs.Finding, "high")
	if c := Compare(a, b); !slices.Equal(c.GotBetter, []string{"PER-1"}) || !slices.Equal(c.NewOrWorse, []string{"SEC-3"}) {
		t.Fatalf("better %q, worse %q", c.GotBetter, c.NewOrWorse)
	}

	// Each score is SCR-2's, as the scorecard shows it; an invalid run has none, and its pair lists nothing.
	c := Compare(baseline(t), baseline(t))
	if want := report.Score(*baseline(t)); c.ScoreBefore == nil || *c.ScoreBefore != (Score{want.Score, want.Of}) || c.ScoreAfter == nil {
		t.Fatalf("score %v, want %d/%d", c.ScoreBefore, want.Score, want.Of)
	}
	a, b = baseline(t), baseline(t)
	set(a, "PER-1", obs.Finding, "low")
	a.Grade.Valid = false
	c = Compare(a, b)
	if c.ScoreBefore != nil || c.ScoreAfter == nil || c.GotBetter == nil || len(c.GotBetter) != 0 || c.NoLongerApplies == nil || c.NotProven == nil || !c.Incomplete {
		t.Fatalf("invalid before: %+v", c)
	}
}

// ownRecipeRun is a real Docker fixture run as a run through a person's own recipe writes it (RCP-4): sandprobe/7,
// run.provider "recipe", the box created by Sandprobe, opt-in kinds, and run.recipe with the recipe's SHA-256.
func ownRecipeRun(t *testing.T) report.Doc {
	t.Helper()
	d := attestedRun(t, false)
	if d.Schema != report.SchemaNoLetter || d.Run.Provider != "exec" || d.Run.Recipe != nil {
		t.Fatalf("the fixture run: %s %s %+v", d.Schema, d.Run.Provider, d.Run.Recipe)
	}
	d.Schema, d.Run.Provider, d.Run.Box.CreatedBySandprobe = report.SchemaOwnRecipe, host.OwnRecipeProvider, true
	d.Run.Recipe = &report.RunRecipe{Own: true, SHA256: strings.Repeat("0123456789abcdef", 4)}
	return d
}

// RCP-4 and ANL-1: a report of a person's own recipe (run.provider "recipe") reads with its record, its opt-in kinds
// and its attestations, since this binary's own policy for it is PRV-15's four as opt-in. A provider_terms kind on it,
// a declared provider beside it, or the same report under a name the policy lacks, is refused.
func TestOwnRecipeReport(t *testing.T) {
	for name, tc := range map[string]struct {
		edit func(d *report.Doc)
		ok   bool
	}{
		"as written":          {func(d *report.Doc) {}, true},
		"a provider_terms":    {func(d *report.Doc) { d.Manifest.SkipKinds["EGR-3"] = obs.SkipProviderTerms }, false},
		"declaring modal":     {func(d *report.Doc) { d.Manifest.DeclaredProvider = "modal" }, false},
		"a name of its own":   {func(d *report.Doc) { d.Run.Provider = "myrecipe" }, false},
		"the header's claim":  {func(d *report.Doc) { d.Run.Provider = "modal" }, false},
		"the recipe's record": {func(d *report.Doc) { d.Run.Provider = "own-0123456789ab" }, false},
	} {
		d := ownRecipeRun(t)
		tc.edit(&d)
		raw, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Parse(raw); (err == nil) != tc.ok {
			t.Errorf("%s: accepted %v, want %v", name, err == nil, tc.ok)
		}
	}
}

// RCP-4, AGT-6 and ANL-1: run.recipe is read only whole, so a reader can rely on it to tell an own-recipe report from
// any other. It is there exactly when run.provider is "recipe" and exactly when the report declares sandprobe/7, with
// own true, a SHA-256 of 64 lowercase hex digits and a box Sandprobe created. Every other shape is refused, and each control beside a forged
// report reads, so the record alone refuses it.
func TestOwnRecipeRecordForged(t *testing.T) {
	sha := strings.Repeat("0123456789abcdef", 4)
	parse := func(d report.Doc, edit func(doc, run map[string]any)) error {
		t.Helper()
		raw, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		var tree map[string]any
		if err := json.Unmarshal(raw, &tree); err != nil {
			t.Fatal(err)
		}
		if edit != nil {
			edit(tree, tree["run"].(map[string]any))
		}
		raw, _ = json.Marshal(tree)
		_, err = Parse(raw)
		return err
	}
	own := ownRecipeRun(t)
	if err := parse(own, nil); err != nil {
		t.Fatalf("the honest report: %v", err)
	}
	whole := func() map[string]any {
		return map[string]any{"own": true, "sha256": sha}
	}
	rec := func(v any) func(doc, run map[string]any) { return func(_, run map[string]any) { run["recipe"] = v } }
	set := func(k string, v any) func(doc, run map[string]any) { // the whole record, one member changed
		r := whole()
		r[k] = v
		return rec(r)
	}
	drop := func(k string) func(doc, run map[string]any) {
		r := whole()
		delete(r, k)
		return rec(r)
	}
	forged := map[string]func(doc, run map[string]any){
		"no record":             func(_, run map[string]any) { delete(run, "recipe") },
		"null":                  rec(nil),
		"empty":                 rec(map[string]any{}),
		"a string":              rec(sha),
		"a list":                rec([]any{whole()}),
		"true":                  rec(true),
		"own false":             set("own", false),
		"own absent":            drop("own"),
		"own null":              set("own", nil),
		"own a string":          set("own", "true"),
		"own a number":          set("own", 1),
		"a path beside":         set("path", "/home/me/recipe.sh"),
		"a provider beside":     set("provider", "modal"),
		"another case of a key": set("SHA256", sha),
		"not created by us":     func(_, run map[string]any) { run["box"].(map[string]any)["created_by_sandprobe"] = false },
		"created_by absent":     func(_, run map[string]any) { delete(run["box"].(map[string]any), "created_by_sandprobe") },
		"under sandprobe/8":     func(doc, _ map[string]any) { doc["schema"] = "sandprobe/8" },
		"with a letter":         func(doc, _ map[string]any) { doc["grade"].(map[string]any)["letter"] = "F" },
		"with a null letter":    func(doc, _ map[string]any) { doc["grade"].(map[string]any)["letter"] = nil },
	}
	forged["digest absent"] = drop("sha256")
	for name, v := range map[string]any{"empty": "", "null": nil, "short": sha[:63], "long": sha + "0", "upper case": strings.ToUpper(sha),
		"not hex": "g" + sha[1:], "with a prefix": "sha256:" + sha, "with a newline": sha + "\n", "a number": 12} {
		forged["digest "+name] = set("sha256", v)
	}
	for name, edit := range forged {
		if err := parse(own, edit); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The record on a report of any other provider: each reads without it, and is refused with it.
	exec := attestedRun(t, false)
	kube := attestedRun(t, false)
	kube.Run.Provider, kube.Run.Box.CreatedBySandprobe = "kubernetes", true
	docker := *baseline(t)
	docker.Schema, docker.Grade.Letter = report.SchemaNoLetter, nil
	docker.Run.Box.CreatedBySandprobe = true
	for name, d := range map[string]report.Doc{"exec": exec, "kubernetes": kube, "docker": docker} {
		if err := parse(d, nil); err != nil {
			t.Fatalf("%s, with no record: %v", name, err)
		}
		if err := parse(d, rec(whole())); err == nil {
			t.Errorf("%s: accepted with a record", name)
		}
		if err := parse(d, set("own", false)); err == nil {
			t.Errorf("%s: accepted with a record that says own is false", name)
		}
		if err := parse(d, rec(nil)); err == nil {
			t.Errorf("%s: accepted with a null record", name)
		}
		// AGT-6: sandprobe/7 is declared only with the record, and the record only on a "recipe" report.
		d.Schema = report.SchemaOwnRecipe
		if err := parse(d, nil); err == nil {
			t.Errorf("%s: accepted as sandprobe/7 with no record", name)
		}
		if err := parse(d, rec(whole())); err == nil {
			t.Errorf("%s: accepted as sandprobe/7 with a record", name)
		}
	}
	// AGT-6: sandprobe/1 to sandprobe/6 never carry the record. As sandprobe/6 the report is refused with it, and
	// without it too, since a "recipe" report always has one.
	six := ownRecipeRun(t)
	six.Schema = report.SchemaNoLetter
	if err := parse(six, nil); err == nil {
		t.Error("sandprobe/6: accepted with the record")
	}
	if err := parse(six, func(_, run map[string]any) { delete(run, "recipe") }); err == nil {
		t.Error("sandprobe/6: a recipe report accepted without the record")
	}
	// The older form of this run reads as run exec wrote it (sandprobe/2, with its letter); the same report as a
	// "recipe" one is refused under every older version, with the record or without it.
	letter := "F"
	old := attestedRun(t, false)
	old.Schema, old.Grade.Letter = report.SchemaFor(old.Manifest), &letter
	if err := parse(old, nil); err != nil || old.Schema != report.SchemaSkipKinds {
		t.Fatalf("the older run exec report (%s): %v", old.Schema, err)
	}
	for _, version := range []string{report.Schema, report.SchemaSkipKinds, report.SchemaHostController, report.SchemaCanaryHTTP, report.SchemaDeclaredProvider} {
		d := ownRecipeRun(t)
		d.Schema, d.Grade.Letter = version, &letter
		if err := parse(d, nil); err == nil {
			t.Errorf("%s: accepted with the record", version)
		}
		if err := parse(d, func(_, run map[string]any) { delete(run, "recipe") }); err == nil {
			t.Errorf("%s: a recipe report accepted without the record", version)
		}
		d = attestedRun(t, false)
		d.Schema, d.Grade.Letter, d.Run.Recipe = version, &letter, own.Run.Recipe
		if err := parse(d, nil); err == nil {
			t.Errorf("%s: a run exec report accepted with the record", version)
		}
	}
}

// CMP-1 and RCP-4: two own-recipe reports of the same run with different recipe SHA-256s, or one with the record
// against the same run with none, are a declared_configuration change and never "no observed change": different host
// code made and deleted the boxes. The same record on both sides is a matched pair.
func TestCompareOwnRecipe(t *testing.T) {
	a, same, other := ownRecipeRun(t), ownRecipeRun(t), ownRecipeRun(t)
	other.Run.Recipe.SHA256 = strings.Repeat("fedcba9876543210", 4)
	none := ownRecipeRun(t) // the same run as run exec wrote it: no record
	none.Schema, none.Run.Provider, none.Run.Recipe = report.SchemaNoLetter, "exec", nil
	bare := ownRecipeRun(t) // the record alone removed, as Compare is handed it
	bare.Run.Recipe = nil
	for _, d := range []report.Doc{a, same, other, none} {
		if raw, _ := json.Marshal(d); func() error { _, err := Parse(raw); return err }() != nil {
			t.Fatalf("a report this test compares doesn't read: %s %+v", d.Run.Provider, d.Run.Recipe)
		}
	}
	if c := Compare(&a, &same); !c.NoObservedChange || len(c.ContextChanges) != 0 {
		t.Errorf("the same record: %+v", c.ContextChanges)
	}
	for name, pair := range map[string][2]*report.Doc{"another SHA-256": {&a, &other}, "another SHA-256, reversed": {&other, &a},
		"no record after": {&a, &bare}, "no record before": {&bare, &a}, "run exec after": {&a, &none}, "run exec before": {&none, &a}} {
		c := Compare(pair[0], pair[1])
		if c.NoObservedChange || !slices.Contains(c.ContextChanges, "declared_configuration") {
			t.Errorf("%s: no observed change %v, %v", name, c.NoObservedChange, c.ContextChanges)
		}
	}
}
