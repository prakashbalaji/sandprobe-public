package main

import (
	"strings"
	"testing"

	"sandprobe/internal/host"
)

func TestNitroReferenceVariantsAndPlan(t *testing.T) {
	for _, variant := range []string{"isolated", "network-isolated", "reference-open", "reference-network-isolated"} {
		spec, err := nitroSpec(variant)
		if err != nil {
			t.Fatal(err)
		}
		reference := strings.HasPrefix(variant, "reference-")
		if spec.Reference != reference || spec.NetworkIsolated != strings.Contains(variant, "network-isolated") {
			t.Fatal("wrong reference or network choice")
		}
		if reference && (spec.Image != host.ReferenceImage || !strings.Contains(spec.Image, "@sha256:")) {
			t.Fatal("reference image not pinned")
		}
		if !reference && spec.Image != podImage {
			t.Fatal("legacy image changed")
		}
		contract, err := host.ReferenceBoundary(spec, "containerd://sha256:"+strings.Repeat("a", 64))
		if err != nil || (contract != nil) != reference {
			t.Fatal("variant declaration mismatch")
		}
		if reference {
			want := "unrestricted"
			if spec.NetworkIsolated {
				want = "deny-canary-six-routes"
			}
			if contract.NetworkExpectation != want {
				t.Fatal("reference requirement does not match variant")
			}
		}
		plan := nitroPlan("/k", &host.SSMCanary{Addr: "203.0.113.10", Dom: "example.test"}, runFlags{variant: variant}, spec)
		if reference && (!strings.Contains(strings.Join(plan.Creates, " "), "UID/GID10001") || !strings.Contains(strings.Join(plan.Runs, " "), "deterministic shell task") || !strings.Contains(plan.LaunchPath, "HOME=/workspace")) {
			t.Fatal("reference not disclosed before approval")
		}
	}
	if _, err := nitroSpec("reference-confidential"); err == nil {
		t.Fatal("unsupported reference mode accepted")
	}
}
