package host

import (
	"context"
	"errors"
	"slices"
	"testing"

	"sandprobe/internal/grade"
	"sandprobe/internal/obs"
)

type uploadSurveyStop struct{ called bool }

func (*uploadSurveyStop) ID() string { return "fixture" }
func (b *uploadSurveyStop) Probe(context.Context, []string, []byte) ([]byte, error) {
	b.called = true
	return nil, errors.New("fixture survey stop")
}

func TestApprovedUploadHostPlan(t *testing.T) {
	hosts := []string{"github.com", "bedrock-runtime.us-west-2.amazonaws.com"}
	o := Options{Mode: "exec", UploadHosts: hosts}
	m, in := Plan(o, &obs.Survey{}, "fixture", Storage{}, "192.0.2.1", "canary.test", "pin")
	if m.Skipped["EGR-6"] != "" || !slices.Contains(m.Selected, "EGR-6") || !slices.Equal(in.Targets["EGR-6"], hosts) || grade.ManifestSound(m) != nil {
		t.Fatal("approved targets did not reach a valid frozen plan")
	}
	hosts[0] = "changed.invalid"
	if m.Targets["EGR-6"][0] != "github.com" {
		t.Fatal("caller mutation changed the frozen plan")
	}
	m.Targets["EGR-6"] = []string{"169.254.169.254"}
	if grade.ManifestSound(m) == nil {
		t.Fatal("manifest accepted an infrastructure address")
	}
	for _, option := range []Options{{UploadHosts: []string{"169.254.169.254"}}, {UploadHosts: []string{"github.com"}, NoCanary: true}} {
		b := &uploadSurveyStop{}
		if _, err := Execute(context.Background(), b, nil, option); err == nil || b.called {
			t.Fatal("invalid selection reached the sandbox")
		}
	}
	b := &uploadSurveyStop{}
	if _, err := Execute(context.Background(), b, nil, Options{UploadHosts: []string{"github.com"}}); err == nil || !b.called {
		t.Fatal("approved options failed before the survey")
	}
}
