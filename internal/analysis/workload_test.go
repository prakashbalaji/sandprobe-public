package analysis

import (
	"slices"
	"strings"
	"testing"

	"sandprobe/internal/obs"
)

func analysisWorkload(box string) *obs.WorkloadContract {
	return &obs.WorkloadContract{Schema: "sandprobe.workload-contract/1", Profile: obs.WorkloadProfile, ManagedRunID: strings.Repeat("a", 16), BoxID: box, Image: "registry.example/agent@sha256:" + strings.Repeat("b", 64), ConfigSHA256: strings.Repeat("c", 64), IdentityPolicySHA256: strings.Repeat("d", 64), TokenCanonical: "/run/secrets/pods.eks.amazonaws.com/serviceaccount/..2026_11_20/eks-pod-identity-token", TokenDevice: 1, TokenInode: 2, ProtectedDevice: 3, ProtectedInode: 4}
}
func TestWorkloadComparisonIncludesAddedRemovedChangedAndInvalidContext(t *testing.T) {
	for _, kind := range []string{"added", "removed", "image", "policy", "alias", "invalid-left", "invalid-right"} {
		t.Run(kind, func(t *testing.T) {
			a, b := loadAWS(t, awsOpen), loadAWS(t, awsOpen)
			a.Manifest.WorkloadContract = analysisWorkload(a.Manifest.BoxID)
			b.Manifest.WorkloadContract = analysisWorkload(b.Manifest.BoxID)
			switch kind {
			case "added":
				a.Manifest.WorkloadContract = nil
			case "removed":
				b.Manifest.WorkloadContract = nil
			case "image":
				b.Manifest.WorkloadContract.Image = "registry.example/other@sha256:" + strings.Repeat("e", 64)
			case "policy":
				b.Manifest.WorkloadContract.IdentityPolicySHA256 = strings.Repeat("e", 64)
			case "alias":
				b.Manifest.WorkloadContract.TokenInode = 999
			case "invalid-left":
				a.Grade.Valid = false
				b.Manifest.WorkloadContract = nil
			case "invalid-right":
				b.Grade.Valid = false
				a.Manifest.WorkloadContract = nil
			}
			c := Compare(a, b)
			if c.NoObservedChange || !slices.Contains(c.ContextChanges, "declared_workload_context") {
				t.Fatal("context change hidden", c)
			}
		})
	}
	a := loadAWS(t, awsOpen)
	a.Manifest.WorkloadContract = analysisWorkload(a.Manifest.BoxID)
	p := Summarize(a)
	a.Manifest.WorkloadContract.TokenInode = 999
	if p.WorkloadContext.TokenInode == 999 {
		t.Fatal("saved analysis context aliases input")
	}
}
