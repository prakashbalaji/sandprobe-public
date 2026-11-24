package analysis

import (
	"encoding/json"
	"maps"
	"os"
	"slices"
	"testing"

	"sandprobe/internal/host"
	"sandprobe/internal/obs"
	"sandprobe/internal/report"
)

// declaredTree is the committed egress-refused report as a canonical sandprobe/5 run exec report whose operator
// declared modal (PRV-17), planned through host.Plan, as a JSON tree for edits no Go struct with omitempty would write.
func declaredTree(t *testing.T) map[string]any {
	t.Helper()
	b, err := os.ReadFile("../../test/reports/egress-refused.json")
	if err != nil {
		t.Fatal(err)
	}
	var d report.Doc
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	excluded := host.ExecExclusions()
	maps.Copy(excluded, host.ModalExcluded)
	o := host.Options{Mode: "exec", Excluded: excluded, ExcludedKind: obs.SkipOptIn, DeclaredProvider: "modal", Existing: true}
	plan, _ := host.Plan(o, &obs.Survey{}, d.Manifest.BoxID, host.Storage{}, "", "", "")
	for id, why := range excluded {
		d.Manifest.Skipped[id], d.Limits.Skipped[id] = why, why
		d.Manifest.Selected = slices.DeleteFunc(d.Manifest.Selected, func(s string) bool { return s == id })
		d.Limits.NotProven = slices.DeleteFunc(d.Limits.NotProven, func(s string) bool { return s == id })
		delete(d.Manifest.Targets, id)
		delete(d.Manifest.Discover, id)
		for i, c := range d.Checks {
			if c.ID == id {
				d.Checks[i] = report.Check{ID: id, Category: c.Category, Title: c.Title, Kind: c.Kind, Result: obs.Skipped, Reason: why, Gets: c.Gets, Fix: c.Fix}
			}
		}
		d.Planned = slices.DeleteFunc(d.Planned, func(c report.Contact) bool { return c.Check == id })
		d.Contacted = slices.DeleteFunc(d.Contacted, func(c report.Contact) bool { return c.Check == id })
	}
	d.Manifest.SkipKinds, d.Manifest.DeclaredProvider, d.Run.Provider = plan.SkipKinds, plan.DeclaredProvider, "exec"
	d.Schema = report.SchemaFor(d.Manifest)
	out, _ := json.Marshal(d)
	var tree map[string]any
	if err := json.Unmarshal(out, &tree); err != nil {
		t.Fatal(err)
	}
	return tree
}

// AGT-6, JON-1 and PRV-17: declared_provider appears only as run exec writes it. A canonical sandprobe/5 report reads;
// the field present but empty or null is refused in any version; sandprobe/5 without it, and the field under an older
// version, are refused.
func TestDeclaredProviderPresentIsCanonical(t *testing.T) {
	for name, tc := range map[string]struct {
		edit func(doc, manifest map[string]any)
		ok   bool
	}{
		"v5, canonical":        {func(d, m map[string]any) {}, true},
		"v5, empty":            {func(d, m map[string]any) { m["declared_provider"] = "" }, false},
		"v5, null":             {func(d, m map[string]any) { m["declared_provider"] = nil }, false},
		"v5, absent":           {func(d, m map[string]any) { delete(m, "declared_provider") }, false},
		"v2, carrying it":      {func(d, m map[string]any) { d["schema"] = report.SchemaSkipKinds }, false},
		"v4, carrying it":      {func(d, m map[string]any) { d["schema"] = report.SchemaCanaryHTTP }, false},
		"v2, empty and opt-in": {func(d, m map[string]any) { d["schema"], m["declared_provider"] = report.SchemaSkipKinds, ""; optIn(m) }, false},
		"v2, absent and opt-in": {func(d, m map[string]any) {
			d["schema"] = report.SchemaSkipKinds
			delete(m, "declared_provider")
			optIn(m)
		}, true},
		"v5, a provider unknown":  {func(d, m map[string]any) { m["declared_provider"] = "nope" }, false},
		"v5, on a native adapter": {func(d, m map[string]any) { d["run"].(map[string]any)["provider"] = "sprites" }, false},
	} {
		tree := declaredTree(t)
		tc.edit(tree, tree["manifest"].(map[string]any))
		b, _ := json.Marshal(tree)
		if _, err := Parse(b); (err == nil) != tc.ok {
			t.Errorf("%s: accepted %v, want %v", name, err == nil, tc.ok)
		}
	}
}

// optIn turns every kind back to run exec's own default, as a report without a declaration carries.
func optIn(m map[string]any) {
	for id := range m["SkipKinds"].(map[string]any) {
		m["SkipKinds"].(map[string]any)[id] = obs.SkipOptIn
	}
}
