package host

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"sandprobe/internal/obs"
)

func hostWorkload() *obs.WorkloadContract {
	return &obs.WorkloadContract{Schema: "sandprobe.workload-contract/1", Profile: obs.WorkloadProfile,
		ManagedRunID: strings.Repeat("a", 16), BoxID: "own-box", Image: "registry.example/agent@sha256:" + strings.Repeat("b", 64),
		ConfigSHA256: strings.Repeat("c", 64), IdentityPolicySHA256: strings.Repeat("d", 64), TokenCanonical: "/run/secrets/pods.eks.amazonaws.com/serviceaccount/..2026_11_20/eks-pod-identity-token",
		TokenDevice: 1, TokenInode: 2, ProtectedDevice: 3, ProtectedInode: 4, PrivateContainerVerified: true, IdentityConfigurationVerified: true, ProtectedFixtureVerified: true}
}
func TestWorkloadPlanIsFrozenAndPlansOnlyFixedProtectedFixture(t *testing.T) {
	c := hostWorkload()
	m, in := Plan(Options{Mode: "exec", ProbeSHA256: "fixed", WorkloadContract: c}, &obs.Survey{}, "own-box", Storage{}, "203.0.113.1", "probe.example", "pin")
	c.IdentityConfigurationVerified = false
	c.TokenCanonical = "changed"
	if !m.WorkloadContract.IdentityConfigurationVerified || m.WorkloadContract.TokenCanonical == "changed" {
		t.Fatal("manifest contract mutated")
	}
	found := false
	for _, path := range in.Targets["SEC-3"] {
		if path == obs.ProtectedMarker {
			found = true
		}
	}
	if !found {
		t.Fatal("protected fixture omitted")
	}
	b, _ := json.Marshal(in)
	if strings.Contains(string(b), "identity_policy_sha256") || strings.Contains(string(b), "token_canonical") {
		t.Fatal("trust-role declaration leaked into guest input")
	}
}
func TestWorkloadRejectsChangedBoxBeforeSurvey(t *testing.T) {
	c := hostWorkload()
	c.BoxID = "another-box"
	if _, err := Execute(context.Background(), &neverWorkloadBox{}, nil, Options{WorkloadContract: c}); err == nil {
		t.Fatal("box mismatch accepted")
	}
}

type neverWorkloadBox struct{}

func (*neverWorkloadBox) ID() string { return "own-box" }
func (*neverWorkloadBox) Probe(context.Context, []string, []byte) ([]byte, error) {
	panic("probe must not run")
}
