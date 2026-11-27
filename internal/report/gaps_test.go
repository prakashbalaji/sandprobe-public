package report

import (
	"encoding/json"
	"reflect"
	"sandprobe/internal/obs"
	"strings"
	"testing"
)

func TestGapPlan(t *testing.T) {
	d := doc(obs.Pass, map[string]Check{"SEC-4": {Result: obs.Skipped}, "EGR-3": {Result: obs.Skipped}, "AMP-6": {Result: obs.Skipped}, "AMP-7": {Result: obs.Skipped}, "AMP-8.blk": {Result: obs.ScopedOut}, "EGR-2": {Result: obs.Unknown}, "EGR-5.80": {Result: obs.Unknown}, "EGR-1": {Result: obs.NotFound}})
	d.Grade.Unknown = []string{"EGR-2", "EGR-5.80"}
	for i := range d.Checks {
		d.Checks[i].Reason = "NEVER_EXPORT_SECRET"
		d.Checks[i].Evidence = "NEVER_EXPORT_GUEST_TEXT"
	}
	d.Manifest.RunID = "run"
	d.Manifest.Nonce = "nonce"
	d.Manifest.BoxID = "box"
	d.Manifest.ProbeSHA256 = strings.Repeat("b", 64)
	before, _ := json.Marshal(d)
	card := Score(d)
	plan, err := MeasurementGapPlan(d, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Conclusive != 20 || plan.Unknown != 2 || plan.Unproven != 1 || plan.Skipped != 4 || plan.ScopedOut != 1 || plan.Prerequisites != "not_recorded" {
		t.Fatal("wrong counts", plan)
	}
	raw, _ := json.Marshal(plan)
	if strings.Contains(string(raw), "NEVER_EXPORT") {
		t.Fatal("raw input leaked")
	}
	find := func(plan GapPlan, id, code string) string {
		for _, g := range plan.Gaps {
			if g.ID == id {
				for _, r := range g.Requirements {
					if r.Code == code {
						return r.Status
					}
				}
			}
		}
		return ""
	}
	if find(plan, "EGR-3", "configured_proxy") != "not_recorded" || find(plan, "AMP-6", "host_connectivity_measurement") != "not_implemented" {
		t.Fatal("masked gap")
	}
	p := &obs.MeasurementPrerequisites{Schema: obs.MeasurementPrerequisitesSchema, RunID: "run", Nonce: "nonce", BoxID: "box", ProbeSHA256: d.Manifest.ProbeSHA256, Proxy: "not_configured", ProxyCredentials: "not_applicable", ProxyProtocol: "not_applicable", KubeAPI: "absent", Vsock: "present"}
	with, err := MeasurementGapPlan(d, p)
	if err != nil {
		t.Fatal(err)
	}
	if find(with, "EGR-3", "configured_proxy") != "not_configured" || find(with, "EGR-3", "assessment_scope") != "requires_review" || find(with, "AMP-7", "kubernetes_target") != "absent" || find(with, "AMP-6", "vsock_device") != "present" || find(with, "AMP-6", "host_connectivity_measurement") != "not_implemented" {
		t.Fatal("independent gates lost")
	}
	after, _ := json.Marshal(d)
	if string(before) != string(after) || !reflect.DeepEqual(card, Score(d)) {
		t.Fatal("analysis changed results or score")
	}
	p.BoxID = "different"
	if _, err = MeasurementGapPlan(d, p); err == nil {
		t.Fatal("accepted unrelated survey")
	}
	p.BoxID = "box"
	p.Proxy = "NEVER_EXPORT"
	if _, err = MeasurementGapPlan(d, p); err == nil {
		t.Fatal("accepted arbitrary enum")
	}
	contradicted := d
	contradicted.Grade.Unknown = nil
	if _, err = MeasurementGapPlan(contradicted, nil); err == nil {
		t.Fatal("accepted contradictory unknown list")
	}
	bad := d
	bad.Grade.Valid = false
	if _, err = MeasurementGapPlan(bad, nil); err == nil {
		t.Fatal("analyzed invalid assessment as conclusive")
	}
	bad = d
	bad.Checks = append([]Check(nil), d.Checks...)
	bad.Checks[0] = bad.Checks[1]
	if _, err = MeasurementGapPlan(bad, nil); err == nil {
		t.Fatal("accepted duplicate")
	}
}

func TestGapPlanDoesNotInventAnInterceptionObservation(t *testing.T) {
	d := doc(obs.NotFound, nil)
	d.Grade.Unknown = []string{"EGR-4"}
	for i := range d.Checks {
		if d.Checks[i].ID == "EGR-4" {
			d.Checks[i].Result = obs.Unknown
		}
	}
	plan, err := MeasurementGapPlan(d, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range plan.Gaps {
		if g.ID == "EGR-4" && strings.Contains(g.Next, "No interception was observed") {
			t.Fatal("invented a negative observation")
		}
	}
}
