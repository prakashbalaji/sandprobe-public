package analysis

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"sandprobe/internal/canary"
	"sandprobe/internal/obs"
	"sandprobe/internal/report"
)

// asV6 makes an older report's tree the report a run writes now: sandprobe/6, with no letter (AGT-6).
func asV6(doc map[string]any) {
	doc["schema"] = report.SchemaNoLetter
	delete(doc["grade"].(map[string]any), "letter")
}

// nitroContract gives a report's tree RUN-17's host-controller contract, on aws-nitro, as sandprobe/3 added it.
func nitroContract(doc, manifest map[string]any) {
	doc["run"].(map[string]any)["provider"] = "aws-nitro"
	manifest["workload_contract"] = &obs.WorkloadContract{Schema: "sandprobe.workload-contract/3", Profile: obs.WorkloadProfile,
		Provider: "aws-nitro", IdentityMode: "host_controller_no_guest_credentials", AgentUID: 10001, AgentGID: 10001,
		ManagedRunID: strings.Repeat("a", 16), BoxID: manifest["BoxID"].(string),
		Image: "registry.example/agent@sha256:" + strings.Repeat("b", 64), ImageContentVerified: true,
		ConfigSHA256: strings.Repeat("c", 64), IdentityPolicySHA256: strings.Repeat("d", 64), AgentHomeSHA256: strings.Repeat("e", 64),
		ProtectedDevice: 3, ProtectedInode: 4}
}

// AGT-6, ANL-1 and GRD-1: sandprobe/1 to sandprobe/5 still read, each exactly the version its fields need and with its
// letter, checked as before; sandprobe/6 carries no letter in any form. Under sandprobe/6 no version says which earlier
// fields a report carries, so each one's own rule is what refuses a forged one.
func TestLetterMatchesSchema(t *testing.T) {
	letter := func(v any) func(d, m map[string]any, c []any) {
		return func(d, m map[string]any, c []any) { d["grade"].(map[string]any)["letter"] = v }
	}
	contract := func(provider string) func(d, m map[string]any, c []any) {
		return func(d, m map[string]any, c []any) {
			asV6(d)
			nitroContract(d, m)
			d["run"].(map[string]any)["provider"] = provider
		}
	}
	for name, tc := range map[string]struct {
		edit func(doc, manifest map[string]any, checks []any)
		ok   bool
	}{
		"v1, as saved":            {func(d, m map[string]any, c []any) {}, true},
		"v1, letter absent":       {func(d, m map[string]any, c []any) { delete(d["grade"].(map[string]any), "letter") }, false},
		"v1, letter null":         {letter(nil), false},
		"v1, letter empty":        {letter(""), false},
		"v1, not one of the five": {letter("E"), false},
		"v1, lower case":          {letter("f"), false},
		"v1, two letters":         {letter("AB"), false},
		"v1, not a string":        {letter(1), false},
		"v1, another of the five": {letter("A"), true}, // unverified, and never used (ANL-1)
		"v6, no letter":           {func(d, m map[string]any, c []any) { asV6(d) }, true},
		"v6, its letter kept":     {func(d, m map[string]any, c []any) { d["schema"] = report.SchemaNoLetter }, false},
		"v6, letter empty":        {func(d, m map[string]any, c []any) { asV6(d); letter("")(d, m, c) }, false},
		"v6, letter null":         {func(d, m map[string]any, c []any) { asV6(d); letter(nil)(d, m, c) }, false},
		"v7":                      {func(d, m map[string]any, c []any) { d["schema"] = "sandprobe/7" }, false},
		"v7, no letter":           {func(d, m map[string]any, c []any) { asV6(d); d["schema"] = "sandprobe/7" }, false},
		"v2, canonical":           {func(d, m map[string]any, c []any) { asV2(d, m) }, true},
		"v2, letter absent":       {func(d, m map[string]any, c []any) { asV6(d); asV2(d, m) }, false},
		"v6, with skip kinds":     {func(d, m map[string]any, c []any) { asV2(d, m); asV6(d) }, true},
		"v6, SkipKinds {}":        {func(d, m map[string]any, c []any) { asV6(d); m["SkipKinds"] = map[string]any{} }, false},
		"v6, SkipKinds null":      {func(d, m map[string]any, c []any) { asV6(d); m["SkipKinds"] = nil }, false},
		"v6, Attested []":         {func(d, m map[string]any, c []any) { asV6(d); m["Attested"] = []any{} }, false},
		"v6, attestation empty":   {func(d, m map[string]any, c []any) { asV6(d); c[0].(map[string]any)["attestation"] = "" }, false},
		"v6, a kind the host lacks": {func(d, m map[string]any, c []any) {
			asV2(d, m)
			asV6(d)
			m["SkipKinds"].(map[string]any)["EGR-3"] = obs.SkipProviderTerms
		}, false},
		"v6, a kind on a tested check": {func(d, m map[string]any, c []any) {
			asV2(d, m)
			asV6(d)
			m["SkipKinds"].(map[string]any)["SEC-1"] = obs.SkipOptIn
		}, false},
		"v6, RUN-17's contract on aws-nitro": {contract("aws-nitro"), true},
		"v6, RUN-17's contract elsewhere":    {contract("daytona"), false},
		"v6, EVD-10's protocol":              {func(d, m map[string]any, c []any) { asV6(d); m["canary_tcp80_protocol"] = canary.HTTPMarkerV1 }, true},
		"v6, a protocol unknown":             {func(d, m map[string]any, c []any) { asV6(d); m["canary_tcp80_protocol"] = "tcp80-other" }, false},
		"v6, protocol empty":                 {func(d, m map[string]any, c []any) { asV6(d); m["canary_tcp80_protocol"] = "" }, false},
	} {
		if _, err := Parse(edited(t, tc.edit)); (err == nil) != tc.ok {
			t.Errorf("%s: accepted %v, want %v", name, err == nil, tc.ok)
		}
	}
	// PRV-17's declared provider, which sandprobe/5 added: under sandprobe/6 its own rules still refuse every forgery.
	for name, tc := range map[string]struct {
		edit func(doc, manifest map[string]any)
		ok   bool
	}{
		"v6, canonical":              {func(d, m map[string]any) {}, true},
		"v6, its letter kept":        {func(d, m map[string]any) { d["grade"].(map[string]any)["letter"] = "F" }, false},
		"v6, empty":                  {func(d, m map[string]any) { m["declared_provider"] = "" }, false},
		"v6, null":                   {func(d, m map[string]any) { m["declared_provider"] = nil }, false},
		"v6, a provider unknown":     {func(d, m map[string]any) { m["declared_provider"] = "nope" }, false},
		"v6, on a native adapter":    {func(d, m map[string]any) { d["run"].(map[string]any)["provider"] = "sprites" }, false},
		"v6, kinds turned opt-in":    {func(d, m map[string]any) { optIn(m) }, false},
		"v6, absent, kinds kept":     {func(d, m map[string]any) { delete(m, "declared_provider") }, false},
		"v6, absent and opt-in":      {func(d, m map[string]any) { delete(m, "declared_provider"); optIn(m) }, true},
		"v6, with EVD-10's protocol": {func(d, m map[string]any) { m["canary_tcp80_protocol"] = canary.HTTPMarkerV1 }, false},
		"v5, letter absent":          {func(d, m map[string]any) { d["schema"] = report.SchemaDeclaredProvider }, false},
	} {
		tree := declaredTree(t)
		asV6(tree)
		tc.edit(tree, tree["manifest"].(map[string]any))
		b, _ := json.Marshal(tree)
		if _, err := Parse(b); (err == nil) != tc.ok {
			t.Errorf("declared, %s: accepted %v, want %v", name, err == nil, tc.ok)
		}
	}
	// An invalid run: sandprobe/6 has no letter key; an earlier version has an empty one, and never a letter.
	invalid := attestedRun(t, true)
	empty, f := "", "F"
	for name, tc := range map[string]struct {
		schema string
		letter *string
		ok     bool
	}{
		"v6, as an invalid run writes it": {report.SchemaNoLetter, nil, true},
		"v6, letter empty":                {report.SchemaNoLetter, &empty, false},
		"v2, letter empty":                {report.SchemaSkipKinds, &empty, true},
		"v2, letter absent":               {report.SchemaSkipKinds, nil, false},
		"v2, a letter":                    {report.SchemaSkipKinds, &f, false},
		"v1, letter empty":                {report.Schema, &empty, false}, // its attestations need sandprobe/2
	} {
		d := invalid
		d.Schema, d.Grade.Letter = tc.schema, tc.letter
		b, _ := json.Marshal(d)
		if _, err := Parse(b); (err == nil) != tc.ok {
			t.Errorf("invalid, %s: accepted %v, want %v", name, err == nil, tc.ok)
		}
	}
}

// ANL-1, ANL-2, CAL-3 and CMP-1: a saved letter is checked, then never used or copied. An older report and the same
// report as sandprobe/6 give the same profile, assessment and comparison, none of which carries a letter, and one
// against the other compares as unchanged.
func TestSavedLetterIsIgnored(t *testing.T) {
	for _, path := range []string{openReport, refusedReport, "../../test/reports/canary-down.json", "../../demo/reports/hardened.json"} {
		old := loadReport(t, path)
		if old.Schema != report.Schema || old.Grade.Letter == nil || *old.Grade.Letter == "" {
			t.Fatalf("%s isn't an older report with a letter", path)
		}
		v6 := *old
		v6.Schema, v6.Grade.Letter = report.SchemaNoLetter, nil
		b, _ := json.Marshal(v6)
		now, err := Parse(b)
		if err != nil {
			t.Fatalf("%s as sandprobe/6 doesn't load: %v", path, err)
		}
		other := "A"
		if *old.Grade.Letter == "A" {
			other = "F"
		}
		relettered := *old
		relettered.Grade.Letter = &other
		for name, d := range map[string]*report.Doc{"as sandprobe/6": now, "with another letter": &relettered} {
			if !reflect.DeepEqual(Summarize(d), Summarize(old)) {
				t.Errorf("%s, %s: the profile changed", path, name)
			}
			a, errA := Assess(d, CanaryDenyProfile)
			if want, errB := Assess(old, CanaryDenyProfile); errA != nil || errB != nil || !reflect.DeepEqual(a, want) {
				t.Errorf("%s, %s: the assessment changed (%v, %v)", path, name, errA, errB)
			}
			c := Compare(old, d)
			if !reflect.DeepEqual(c, Compare(old, old)) || len(c.ContextChanges) != 0 || len(c.NewOrWorse) != 0 || len(c.CoverageLoss) != 0 {
				t.Errorf("%s, %s: compared as changed: %+v", path, name, c)
			}
		}
		a, _ := Assess(old, CanaryDenyProfile)
		for name, v := range map[string]any{"profile": Summarize(old), "assessment": a, "comparison": Compare(old, old)} {
			out, _ := json.Marshal(v)
			if s := string(out); strings.Contains(s, `"`+*old.Grade.Letter+`"`) || strings.Contains(s, "letter") || strings.Contains(s, "reported_grade") {
				t.Errorf("%s: the %s carries the saved letter: %s", path, name, s)
			}
		}
		if p := Summarize(old); p.Schema != "sandprobe.profile/2" || a.Schema != "sandprobe.assessment/2" || a.Coverage.Schema != p.Schema {
			t.Errorf("%s: output versions %s, %s", path, p.Schema, a.Schema)
		}
	}
}

var reportData = regexp.MustCompile(`(?s)<script id="report-data" type="application/json">(.*?)</script>`)

// SCR-3, OUT-2 and AGT-6: the page -out re-renders from an older report embeds a report this reader takes: the saved
// one as sandprobe/6, with no letter and nothing else changed. It holds for each earlier version and the fields that
// version added, and for an invalid run, which stays invalid with its reason. Without the new version the embedded
// document would declare a version that requires the letter it no longer has, and be refused.
func TestReRenderedPageReadsBack(t *testing.T) {
	tree := func(edit func(doc, manifest map[string]any)) []byte {
		return edited(t, func(d, m map[string]any, _ []any) { edit(d, m) })
	}
	declaredV5, _ := json.Marshal(declaredTree(t))
	legacy := func(d report.Doc, letter string) []byte { // a run exec report with attestations, as sandprobe/2 wrote it
		d.Schema, d.Grade.Letter = report.SchemaSkipKinds, &letter
		b, _ := json.Marshal(d)
		return b
	}
	saved := map[string]struct {
		raw    []byte
		schema string
	}{
		"v2, skip kinds":        {tree(asV2), report.SchemaSkipKinds},
		"v2, attested":          {legacy(attestedRun(t, false), "F"), report.SchemaSkipKinds},
		"v2, invalid":           {legacy(attestedRun(t, true), ""), report.SchemaSkipKinds},
		"v3, RUN-17's contract": {tree(func(d, m map[string]any) { d["schema"] = report.SchemaHostController; nitroContract(d, m) }), report.SchemaHostController},
		"v4, EVD-10's protocol": {tree(func(d, m map[string]any) {
			d["schema"], m["canary_tcp80_protocol"] = report.SchemaCanaryHTTP, canary.HTTPMarkerV1
		}), report.SchemaCanaryHTTP},
		"v5, a declared provider": {declaredV5, report.SchemaDeclaredProvider},
		"v6, as a run writes it":  {tree(func(d, m map[string]any) { asV6(d) }), report.SchemaNoLetter},
	}
	for _, pat := range []string{"../../demo/reports/*.json", "../../test/reports/*.json"} {
		files, _ := filepath.Glob(pat)
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			saved["v1, "+f] = struct {
				raw    []byte
				schema string
			}{b, report.Schema}
		}
	}
	if len(saved) < 13 {
		t.Fatalf("saved reports: %d", len(saved))
	}
	for name, tc := range saved {
		old, err := Parse(tc.raw)
		if err != nil || old.Schema != tc.schema || (old.Grade.Letter != nil) != (tc.schema != report.SchemaNoLetter) {
			t.Fatalf("%s: the saved report isn't a %s one this reader takes: %v", name, tc.schema, err)
		}
		if invalid := name == "v2, invalid"; invalid == old.Grade.Valid || invalid && (old.Grade.Invalid == "" || *old.Grade.Letter != "") {
			t.Fatalf("%s: valid %v, reason %q", name, old.Grade.Valid, old.Grade.Invalid)
		}
		for _, theme := range []string{"graphite", "mission"} {
			page, err := report.SavedHTML(*old, theme)
			if err != nil {
				t.Fatal(err)
			}
			m := reportData.FindSubmatch(page)
			if m == nil {
				t.Fatalf("%s: the page has no report-data", name)
			}
			got, err := Parse(m[1])
			if err != nil {
				t.Errorf("%s, %s: the page's embedded report is refused: %v", name, theme, err)
				continue
			}
			want := *old
			want.Schema, want.Grade.Letter = report.SchemaNoLetter, nil
			a, _ := json.Marshal(got)
			b, _ := json.Marshal(want)
			if got.Schema != report.SchemaNoLetter || got.Grade.Letter != nil || bytes.Contains(m[1], []byte(`"letter"`)) || !bytes.Equal(a, b) {
				t.Errorf("%s, %s: the embedded report declares %s, or differs from the saved one in more than the version and the letter", name, theme, got.Schema)
			}
			if got.Grade.Valid != old.Grade.Valid || got.Grade.Invalid != old.Grade.Invalid || got.Grade.Complete != old.Grade.Complete {
				t.Errorf("%s, %s: validity changed: %+v", name, theme, got.Grade)
			}
			if !bytes.Contains(page, []byte("report schema "+report.SchemaNoLetter+" ")) {
				t.Errorf("%s, %s: the footer doesn't name the embedded report's version", name, theme)
			}
		}
		if old.Schema != tc.schema || (old.Grade.Letter != nil) != (tc.schema != report.SchemaNoLetter) {
			t.Errorf("%s: rendering changed the caller's report", name)
		}
	}
}
