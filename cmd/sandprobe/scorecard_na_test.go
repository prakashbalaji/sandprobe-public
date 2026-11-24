package main

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"sandprobe/internal/host"
	"sandprobe/internal/obs"
	"sandprobe/internal/report"
)

// SCR-2: every adapter that excludes provider endpoints records why: run exec's and a recipe's defaults are opt-in,
// and every other adapter's exclusions come from its PRV row, the provider's terms.
func TestExclusionKinds(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	n := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			lit, ok := node.(*ast.CompositeLit)
			if !ok {
				return true
			}
			if sel, ok := lit.Type.(*ast.SelectorExpr); !ok || sel.Sel.Name != "Options" {
				return true
			}
			fields := map[string]string{}
			for _, e := range lit.Elts {
				if kv, ok := e.(*ast.KeyValueExpr); ok {
					if sel, ok := kv.Value.(*ast.SelectorExpr); ok {
						fields[kv.Key.(*ast.Ident).Name] = sel.Sel.Name
					} else {
						fields[kv.Key.(*ast.Ident).Name] = "set"
					}
				}
			}
			if fields["Excluded"] == "" {
				return true
			}
			n++
			want := "SkipProviderTerms"
			if f == "exec.go" || f == "recipe.go" {
				want = "SkipOptIn"
			}
			if fields["ExcludedKind"] != want {
				t.Errorf("%s: an exclusion recorded as %q, want obs.%s", f, fields["ExcludedKind"], want)
			}
			return true
		})
	}
	if n < 11 { // nine native adapters (Modal's PoC among them), run exec and the recipe runner
		t.Fatalf("found %d exclusions", n)
	}
}

// skipSaved is a saved Docker report as a run with these options would have written it: each excluded check skipped
// with host.Plan's reason and kind, and gone from the selection, its plan and the not-proven list.
func skipSaved(t *testing.T, provider string, o host.Options) string {
	t.Helper()
	b, err := os.ReadFile("../../test/reports/egress-refused.json")
	if err != nil {
		t.Fatal(err)
	}
	var d report.Doc
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	plan, _ := host.Plan(o, &obs.Survey{}, d.Manifest.BoxID, host.Storage{}, "", "", "")
	for id := range o.Excluded {
		why := plan.Skipped[id]
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
	d.Manifest.SkipKinds, d.Run.Provider = plan.SkipKinds, provider
	d.Schema = report.SchemaFor(d.Manifest) // AGT-6: the version its fields need
	out, _ := json.Marshal(d)
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// SCR-2 end to end: a native adapter's report reads "Score x/5" with Cloud access not applicable and named on its
// own line; run exec's and run kubernetes's read x/6, Cloud access red with the opt-in hint.
func TestScorecardNotApplicable(t *testing.T) {
	rc, err := shippedRecipe("kubernetes")
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		o          host.Options
		score, row string
	}{
		"sprites": {host.Options{Excluded: host.SpritesExclusions(), ExcludedKind: obs.SkipProviderTerms}, "Score 2/5\nCloud access isn't counted: the provider's terms exclude its own endpoints (" + host.SpritesExclusions()["SEC-4"] + ")\n",
			"N/A    Cloud access  Can it use your cloud identity?\n                         " + report.NotApplicable + "\n"},
		"e2b": {host.Options{Excluded: host.E2BExclusions(), ExcludedKind: obs.SkipProviderTerms}, "Score 2/5\nCloud access isn't counted: the provider's terms exclude its own endpoints (" + host.E2BExclusions()["SEC-4"] + "; " + host.E2BExclusions()["AMP-7"] + ")\n",
			"N/A    Cloud access"},
		"exec": {host.Options{Excluded: host.ExecExclusions(), ExcludedKind: obs.SkipOptIn}, "Score 2/6\n\n",
			"RED    Cloud access  Can it use your cloud identity?\n                         Not tested: opt in with -provider-endpoints SEC-4,AMP-7 if your provider's terms allow\n"},
		"kubernetes": {host.Options{Excluded: recipeExclusions(rc), ExcludedKind: obs.SkipOptIn}, "Score 2/6\n\n",
			"Not tested: opt in with -provider-endpoints SEC-4,AMP-7 if your provider's terms allow\n"},
	} {
		in := skipSaved(t, name, tc.o)
		var out, errs bytes.Buffer
		if code := run([]string{"scorecard", in}, &out, &errs); code != exitGraded {
			t.Fatalf("%s: exit %d, %s", name, code, errs.String())
		}
		// UX-9 wraps long lines at 80 columns, so content is compared with whitespace folded; a score with no
		// not-counted line ("Score 2/6\n\n") is still matched exactly.
		s := out.String()
		if strings.HasSuffix(tc.score, "\n\n") && !strings.Contains(s, tc.score) || !strings.Contains(flat(s), flat(tc.score)) || !strings.Contains(flat(s), flat(tc.row)) {
			t.Errorf("%s: want %q and %q in:\n%s", name, tc.score, tc.row, s)
		}
		out.Reset()
		if code := run([]string{"scorecard", in, "-o", "json"}, &out, &errs); code != exitGraded {
			t.Fatalf("%s: json exit %d", name, code)
		}
		var c report.Card
		if err := json.Unmarshal(out.Bytes(), &c); err != nil {
			t.Fatal(err)
		}
		na := strings.Contains(tc.score, "/5")
		if r := c.Rows[4]; r.Name != "Cloud access" || r.NotApplicable != na || r.Green || (c.Of == 5) != na || c.Score == c.Of && c.Of == 6 {
			t.Errorf("%s: the card's JSON: %d/%d %+v", name, c.Score, c.Of, r)
		}
	}
}

// SCR-2 and HCN-5 end to end: a run without a canary still reads Exfiltration "not tested: run without a canary",
// red, and the run is incomplete (exit 5); nothing leaves the score.
func TestScorecardNoCanaryStaysRed(t *testing.T) {
	b, err := os.ReadFile("../../test/reports/canary-down.json")
	if err != nil {
		t.Fatal(err)
	}
	var d report.Doc
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	d.Run.NoCanary, d.Manifest.NoCanary = true, true
	out, _ := json.Marshal(d)
	in := filepath.Join(t.TempDir(), "report.json")
	os.WriteFile(in, out, 0o644)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"scorecard", in}, &stdout, &stderr); code != exitPartial {
		t.Fatalf("exit %d, %s", code, stderr.String())
	}
	if s := stdout.String(); !strings.Contains(s, "Score 2/6\n") || !strings.Contains(s, "RED    Exfiltration  Can data leave the box?\n                         Not tested: run without a canary\n") || strings.Contains(s, "N/A") {
		t.Errorf("no canary:\n%s", s)
	}
}

// CMP-1 and SCR-2: compare never reads a newly not-applicable category as like-for-like. Tested to skipped is
// coverage loss, a changed set of provider-terms skips is a changed setup (exit 5), and only a matched context reads
// unchanged. A report from before skip kinds and a new opt-in one of the same box are a matched pair: both read
// "Not tested" out of six.
func TestCompareNotApplicable(t *testing.T) {
	tested := "../../test/reports/egress-refused.json"
	terms := skipSaved(t, "sprites", host.Options{Excluded: host.SpritesExclusions(), ExcludedKind: obs.SkipProviderTerms})
	optIn := skipSaved(t, "exec", host.Options{Excluded: host.ExecExclusions(), ExcludedKind: obs.SkipOptIn})
	noKind := skipSaved(t, "exec", host.Options{Excluded: host.ExecExclusions()})
	for name, tc := range map[string]struct {
		before, after string
		code          int
		loss          bool
	}{
		"tested, then not applicable":     {tested, terms, exitPartial, true},
		"opt-in, then not applicable":     {optIn, terms, exitPartial, false},
		"not applicable in both, matched": {terms, terms, exitGraded, false},
		"no kind, then opt-in, matched":   {noKind, optIn, exitGraded, false},
	} {
		var out, errs bytes.Buffer
		code := run([]string{"compare", tc.before, tc.after, "-o", "json"}, &out, &errs)
		var c struct {
			CoverageLoss     []string `json:"coverage_loss"`
			ContextChanges   []string `json:"context_changes"`
			NoObservedChange bool     `json:"no_observed_change"`
		}
		json.Unmarshal(out.Bytes(), &c)
		matched := tc.code == exitGraded
		if code != tc.code || slices.Contains(c.CoverageLoss, "SEC-4") != tc.loss || c.NoObservedChange != matched ||
			slices.Contains(c.ContextChanges, "declared_configuration") == matched {
			t.Errorf("%s: exit %d, %+v", name, code, c)
		}
	}
}

// ANL-1 and SCR-2: a saved report whose skip kinds the host couldn't have written is refused, never scored.
func TestScorecardRefusesForgedKinds(t *testing.T) {
	for name, kinds := range map[string]map[string]string{
		"a tested check":  {"SEC-4": obs.SkipProviderTerms},
		"not an endpoint": {"EGR-6": obs.SkipProviderTerms},
		"not a kind":      {"EGR-3": "terms"},
	} {
		b, _ := os.ReadFile("../../test/reports/egress-refused.json")
		var d report.Doc
		if err := json.Unmarshal(b, &d); err != nil {
			t.Fatal(err)
		}
		d.Manifest.SkipKinds = kinds
		d.Schema = report.SchemaFor(d.Manifest) // refused for the kind, never for the version
		out, _ := json.Marshal(d)
		in := filepath.Join(t.TempDir(), "report.json")
		os.WriteFile(in, out, 0o644)
		var stdout, stderr bytes.Buffer
		if code := run([]string{"scorecard", in}, &stdout, &stderr); code != exitUsage || strings.Contains(stdout.String(), "Score") {
			t.Errorf("%s: exit %d, %s", name, code, stdout.String())
		}
	}
}

// AGT-6 at the command line: a sandprobe/1 report still reads; a report with skip kinds declares sandprobe/2 and
// reads; a sandprobe/1 report carrying skip kinds, a sandprobe/2 one without them, and a version this build doesn't
// know are refused, with a fix that names the versions it reads.
func TestReportSchemaVersions(t *testing.T) {
	v2 := skipSaved(t, "sprites", host.Options{Excluded: host.SpritesExclusions(), ExcludedKind: obs.SkipProviderTerms})
	retag := func(src, schema string) string {
		b, _ := os.ReadFile(src)
		var d report.Doc
		json.Unmarshal(b, &d)
		d.Schema = schema
		out, _ := json.Marshal(d)
		path := filepath.Join(t.TempDir(), "report.json")
		os.WriteFile(path, out, 0o644)
		return path
	}
	for name, tc := range map[string]struct {
		path string
		code int
	}{
		"sandprobe/1, as before":            {"../../test/reports/egress-refused.json", exitGraded},
		"sandprobe/2 with skip kinds":       {v2, exitGraded},
		"sandprobe/1 carrying skip kinds":   {retag(v2, "sandprobe/1"), exitUsage},
		"sandprobe/2 without skip kinds":    {retag("../../test/reports/egress-refused.json", "sandprobe/2"), exitUsage},
		"a version this build doesn't know": {retag(v2, "sandprobe/9"), exitUsage},
	} {
		var out, errs bytes.Buffer
		code := run([]string{"scorecard", tc.path}, &out, &errs)
		if code != tc.code || code == exitUsage && !strings.Contains(errs.String(), "sandprobe/1 or sandprobe/2 or sandprobe/3 or sandprobe/4 report file") {
			t.Errorf("%s: exit %d, %s", name, code, errs.String())
		}
	}
	b, _ := os.ReadFile(v2)
	if !bytes.Contains(b, []byte(`"schema":"sandprobe/2"`)) {
		t.Error("a report with skip kinds doesn't declare sandprobe/2")
	}
}

// SCR-2 and ANL-1, the security review's forgery: a valid saved run exec report whose SEC-4 and AMP-7 kinds are edited
// from opt_in to provider_terms is refused, never scored out of five; scored directly, the edit changes nothing,
// since run exec's own policy is opt_in.
func TestScorecardRefusesForgedProvenance(t *testing.T) {
	honest := skipSaved(t, "exec", host.Options{Excluded: host.ExecExclusions(), ExcludedKind: obs.SkipOptIn})
	var out, errs bytes.Buffer
	if code := run([]string{"scorecard", honest}, &out, &errs); code != exitGraded || !strings.Contains(out.String(), "Score 2/6\n") {
		t.Fatalf("the honest report: exit %d\n%s%s", code, out.String(), errs.String())
	}
	b, _ := os.ReadFile(honest)
	var d report.Doc
	json.Unmarshal(b, &d)
	d.Manifest.SkipKinds["SEC-4"], d.Manifest.SkipKinds["AMP-7"] = obs.SkipProviderTerms, obs.SkipProviderTerms
	forged, _ := json.Marshal(d)
	in := filepath.Join(t.TempDir(), "forged.json")
	os.WriteFile(in, forged, 0o644)
	out.Reset()
	if code := run([]string{"scorecard", in}, &out, &errs); code != exitUsage || strings.Contains(out.String(), "/5") {
		t.Errorf("the forged report: exit %d\n%s", code, out.String())
	}
	if c := report.Score(d); c.Of != 6 || c.Rows[4].NotApplicable || c.Rows[4].Green {
		t.Errorf("scored directly: %d/%d %+v", c.Score, c.Of, c.Rows[4])
	}
}

// ANL-1: every offline rendering of a saved report says plainly that it wasn't re-verified; a run's own page doesn't.
func TestOfflineRenderingsSayNotReVerified(t *testing.T) {
	saved := "../../test/reports/egress-refused.json"
	dir := t.TempDir()
	for _, args := range [][]string{{"scorecard", saved}, {"scorecard", saved, "-out", dir}, {"profile", saved},
		{"assess", saved, "canary-egress-deny-v1"}, {"compare", saved, saved}} {
		var out, errs bytes.Buffer
		run(args, &out, &errs)
		if !strings.Contains(flat(out.String()), report.SavedNote) {
			t.Errorf("%q doesn't say it wasn't re-verified:\n%s", args, out.String())
		}
	}
	pages, _ := filepath.Glob(filepath.Join(dir, "*.html"))
	if len(pages) != 1 {
		t.Fatalf("pages: %v", pages)
	}
	if b, _ := os.ReadFile(pages[0]); !strings.Contains(string(b), "From a saved report: structurally checked only.") {
		t.Error("the re-rendered page doesn't say it wasn't re-verified")
	}
	var out, errs bytes.Buffer
	run([]string{"scorecard", saved, "-o", "json"}, &out, &errs)
	if !strings.Contains(out.String(), `"verification": "structural_only_unauthenticated"`) {
		t.Errorf("the card's JSON: %s", out.String())
	}
}

// flat folds every run of whitespace, line breaks included, to one space: text UX-9 wraps at 80 columns still
// matches its unwrapped form.
func flat(s string) string { return strings.Join(strings.Fields(s), " ") }
