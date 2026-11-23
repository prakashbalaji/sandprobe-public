package analysis

import (
	"encoding/json"
	"os"
	"testing"

	"sandprobe/internal/obs"
)

// edited is a committed sandprobe/1 fixture as a JSON tree, changed by edit, so a field can be written present but
// empty or null, which no Go struct with omitempty would write.
func edited(t *testing.T, edit func(doc, manifest map[string]any, checks []any)) []byte {
	t.Helper()
	b, err := os.ReadFile("../../test/reports/egress-refused.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	edit(doc, doc["manifest"].(map[string]any), doc["checks"].([]any))
	out, _ := json.Marshal(doc)
	return out
}

// asV2 makes the fixture a canonical sandprobe/2 report: a run exec whose survey-skipped EGR-3 and AMP-6 carry their
// opt-in kind, as run exec's policy derives (SCR-2).
func asV2(doc, manifest map[string]any) {
	doc["schema"] = "sandprobe/2"
	doc["run"].(map[string]any)["provider"] = "exec"
	manifest["SkipKinds"] = map[string]any{"EGR-3": obs.SkipOptIn, "AMP-6": obs.SkipOptIn}
}

// AGT-6 and JON-1, the security re-review of #8: sandprobe/2's fields appear only as the writer gives them. A
// sandprobe/1 report refuses each one present in any form, empty or null included, and so does a sandprobe/2 report
// for an empty or null one; absent, each version reads as before.
func TestNewFieldsPresentAreCanonical(t *testing.T) {
	noEdit := func(doc, manifest map[string]any, checks []any) {}
	for name, tc := range map[string]struct {
		edit func(doc, manifest map[string]any, checks []any)
		ok   bool
	}{
		"v1, absent": {noEdit, true},
		"v1, SkipKinds {} (the reviewer's reproduction)": {func(d, m map[string]any, c []any) { m["SkipKinds"] = map[string]any{} }, false},
		"v1, SkipKinds null":                             {func(d, m map[string]any, c []any) { m["SkipKinds"] = nil }, false},
		"v1, Attested []":                                {func(d, m map[string]any, c []any) { m["Attested"] = []any{} }, false},
		"v1, Attested null":                              {func(d, m map[string]any, c []any) { m["Attested"] = nil }, false},
		"v1, attestation empty":                          {func(d, m map[string]any, c []any) { c[0].(map[string]any)["attestation"] = "" }, false},
		"v1, attestation null":                           {func(d, m map[string]any, c []any) { c[0].(map[string]any)["attestation"] = nil }, false},
		"v2, canonical":                                  {func(d, m map[string]any, c []any) { asV2(d, m) }, true},
		"v2, Attested []":                                {func(d, m map[string]any, c []any) { asV2(d, m); m["Attested"] = []any{} }, false},
		"v2, Attested null":                              {func(d, m map[string]any, c []any) { asV2(d, m); m["Attested"] = nil }, false},
		"v2, attestation null":                           {func(d, m map[string]any, c []any) { asV2(d, m); c[0].(map[string]any)["attestation"] = nil }, false},
		"v2, SkipKinds {} and nothing else new":          {func(d, m map[string]any, c []any) { asV2(d, m); m["SkipKinds"] = map[string]any{} }, false},
		"v2, SkipKinds null and nothing else new":        {func(d, m map[string]any, c []any) { asV2(d, m); m["SkipKinds"] = nil }, false},
		"v2, absent new fields":                          {func(d, m map[string]any, c []any) { d["schema"] = "sandprobe/2" }, false},
	} {
		if _, err := Parse(edited(t, tc.edit)); (err == nil) != tc.ok {
			t.Errorf("%s: accepted %v, want %v", name, err == nil, tc.ok)
		}
	}
}
