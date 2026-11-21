package host

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"sandprobe/internal/grade"
	"sandprobe/internal/obs"
)

func TestReferenceBoundaryPair(t *testing.T) {
	spec := PodSpec{Reference: true, RuntimeClass: "isolated-sandbox", Image: ReferenceImage}
	open, err := ReferenceBoundary(spec, testReferenceID)
	if err != nil {
		t.Fatal(err)
	}
	spec.NetworkIsolated = true
	isolated, err := ReferenceBoundary(spec, testReferenceID)
	if err != nil {
		t.Fatal(err)
	}
	if open.NetworkExpectation != "unrestricted" || isolated.NetworkExpectation != "deny-canary-six-routes" || open.ProtectedResourceAttribution != "unestablished" {
		t.Fatal("wrong declared policy or invented attribution")
	}
	isolated.NetworkExpectation = open.NetworkExpectation
	if !reflect.DeepEqual(open, isolated) {
		t.Fatal("pair context differs beyond network expectation")
	}
	if c, err := ReferenceBoundary(PodSpec{}, ""); c != nil || err != nil {
		t.Fatal("legacy context invented")
	}
	for _, tc := range []struct {
		spec PodSpec
		id   string
	}{
		{PodSpec{Reference: true, RuntimeClass: "changed", Image: ReferenceImage}, testReferenceID},
		{PodSpec{Reference: true, RuntimeClass: "isolated-sandbox", Image: "mutable:tag"}, testReferenceID},
		{spec, ""},
	} {
		if c, err := ReferenceBoundary(tc.spec, tc.id); err == nil || c != nil {
			t.Fatal("unsupported reference declaration accepted")
		}
	}
}

func TestBoundaryPlanCopyAndLegacyGrade(t *testing.T) {
	c, err := ReferenceBoundary(PodSpec{Reference: true, RuntimeClass: "isolated-sandbox", Image: ReferenceImage}, testReferenceID)
	if err != nil {
		t.Fatal(err)
	}
	m, in := Plan(Options{Mode: "exec", ProbeSHA256: "abc", BoundaryContract: c}, &obs.Survey{}, "box", Storage{}, "203.0.113.1", "example.test", "pin")
	if m.BoundaryContract == nil || m.BoundaryContract == c {
		t.Fatal("manifest did not copy context")
	}
	c.AgentUID = 0
	if m.BoundaryContract.AgentUID != 10001 {
		t.Fatal("caller rewrote planned context")
	}
	b, _ := json.Marshal(in)
	if strings.Contains(string(b), "boundary") || strings.Contains(string(b), "unestablished") {
		t.Fatal("host declaration leaked to probe stdin")
	}
	d := &obs.Doc{Schema: obs.Schema, RunID: m.RunID, Nonce: m.Nonce, BoxID: m.BoxID, ProbeSHA256: m.ProbeSHA256, Identity: &obs.Identity{CapEff: "0", NoNewPrivs: new(int)}}
	with := grade.Grade(m, d, nil)
	m.BoundaryContract = nil
	without := grade.Grade(m, d, nil)
	if !with.Valid || !reflect.DeepEqual(with, without) {
		t.Fatal("declaration changed legacy grade/checks")
	}
	// Execute must reject before even the survey; nil dependencies would panic.
	if _, err := Execute(context.Background(), nil, nil, Options{BoundaryContract: c}); err == nil {
		t.Fatal("malformed declaration reached execution")
	}
}
