package host

import (
	"context"
	"encoding/json"
	"maps"
	"strings"
	"testing"

	"sandprobe/internal/canary"
	"sandprobe/internal/grade"
	"sandprobe/internal/obs"
)

// PRV-17: a declared provider's PRV-row entry decides its checks on run exec: each is skipped with the entry's own
// reason and kind provider_terms, the manifest records the name, and the probe's input carries neither. Execute
// refuses a name the table lacks, a run that isn't run exec's, and exclusions that differ from the entry.
func TestPlanDeclaredProvider(t *testing.T) {
	excluded := ExecExclusions()
	maps.Copy(excluded, ModalExcluded)
	o := Options{Mode: "exec", Excluded: excluded, ExcludedKind: obs.SkipOptIn, DeclaredProvider: "modal", Existing: true}
	m, in := Plan(o, &obs.Survey{Vsock: true}, "box-1", Storage{}, "", "", "")
	want := map[string]string{"SEC-4": obs.SkipProviderTerms, "EGR-3": obs.SkipProviderTerms, "AMP-6": obs.SkipProviderTerms, "AMP-7": obs.SkipProviderTerms}
	if m.DeclaredProvider != "modal" || !maps.Equal(m.SkipKinds, want) {
		t.Fatalf("declared %q, kinds %v", m.DeclaredProvider, m.SkipKinds)
	}
	for id, why := range ModalExcluded {
		if m.Skipped[id] != why {
			t.Errorf("%s: skipped for %q", id, m.Skipped[id])
		}
	}
	if b, _ := json.Marshal(in); strings.Contains(string(b), "declared") || strings.Contains(string(b), "modal") || strings.Contains(string(b), obs.SkipProviderTerms) {
		t.Errorf("the probe's input carries the declaration: %s", b)
	}
	if err := grade.ManifestSound(m); err != nil {
		t.Fatalf("the grader refused the manifest: %v", err)
	}
	if err := checkDeclared(o); err != nil {
		t.Fatalf("the honest options were refused: %v", err)
	}
	for name, edit := range map[string]func(*Options){
		"a name the table lacks":        func(o *Options) { o.DeclaredProvider = "aws-nitro" },
		"a differently cased key":       func(o *Options) { o.DeclaredProvider = "Modal" },
		"a native adapter's kind":       func(o *Options) { o.ExcludedKind = obs.SkipProviderTerms },
		"no kind":                       func(o *Options) { o.ExcludedKind = "" },
		"run exec's own reasons":        func(o *Options) { o.Excluded = ExecExclusions() },
		"another provider's reasons":    func(o *Options) { o.Excluded = SpritesExclusions() },
		"an excluded check lifted":      func(o *Options) { o.Excluded = maps.Clone(excluded); delete(o.Excluded, "SEC-4") },
		"with EVD-10's TCP/80 protocol": func(o *Options) { o.CanaryTCP80Protocol = canary.HTTPMarkerV1 },
		"with a workload contract":      func(o *Options) { o.WorkloadContract = &obs.WorkloadContract{} },
	} {
		bad := o
		edit(&bad)
		if checkDeclared(bad) == nil {
			t.Errorf("%s: accepted", name)
		}
		if _, err := Execute(context.Background(), surveyBox{}, nil, bad); err == nil {
			t.Errorf("%s: Execute accepted it", name)
		}
	}
}
