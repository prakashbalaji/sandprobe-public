package obs

import (
	"encoding/json"
	"strings"
	"testing"
)

func workloadDeclaration() *WorkloadContract {
	return &WorkloadContract{Schema: "sandprobe.workload-contract/1", Profile: WorkloadProfile, ManagedRunID: strings.Repeat("a", 16), BoxID: "original", Image: "registry.example/agent@sha256:" + strings.Repeat("b", 64), ConfigSHA256: strings.Repeat("c", 64), IdentityPolicySHA256: strings.Repeat("d", 64), TokenCanonical: "/run/secrets/pods.eks.amazonaws.com/serviceaccount/..2026_11_20/eks-pod-identity-token", TokenDevice: 1, TokenInode: 2, ProtectedDevice: 3, ProtectedInode: 4}
}
func TestWorkloadDeclarationHasFixedPolicyAndBoundContext(t *testing.T) {
	if ValidateWorkloadContract(nil) != nil {
		t.Fatal("legacy missing context rejected")
	}
	if ValidateWorkloadContract(workloadDeclaration()) != nil {
		t.Fatal("valid declaration rejected")
	}
	for _, change := range []func(*WorkloadContract){func(c *WorkloadContract) { c.Profile = "allow-everything" }, func(c *WorkloadContract) { c.TokenCanonical = "/arbitrary/credential" }, func(c *WorkloadContract) { c.TokenInode = 0 }, func(c *WorkloadContract) { c.ProtectedInode = 0 }, func(c *WorkloadContract) { c.IdentityPolicySHA256 = "unverified" }, func(c *WorkloadContract) { c.Image = "mutable:latest" }} {
		c := workloadDeclaration()
		change(c)
		if ValidateWorkloadContract(c) == nil {
			t.Fatal("unsafe declaration accepted")
		}
	}
}

// WGR-7: no provider can inherit Nitro's identity permission by changing a label.
func TestPortableWorkloadDeclaration(t *testing.T) {
	portable := func() *WorkloadContract {
		c := workloadDeclaration()
		c.Schema = "sandprobe.workload-contract/2"
		c.Provider = "daytona"
		c.IdentityMode = "host_controller_no_guest_credentials"
		c.AgentUID, c.AgentGID = 1001, 1001
		c.TokenCanonical, c.TokenDevice, c.TokenInode = "", 0, 0
		return c
	}
	if err := ValidateWorkloadContract(portable()); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*WorkloadContract){
		func(c *WorkloadContract) { c.Schema = "sandprobe.workload-contract/3" },
		func(c *WorkloadContract) { c.Provider = "aws-nitro" },
		func(c *WorkloadContract) { c.IdentityMode = "guest_credentials" },
		func(c *WorkloadContract) { c.AgentUID = 0 },
		func(c *WorkloadContract) { c.AgentGID = -1 },
		func(c *WorkloadContract) { c.TokenCanonical = workloadDeclaration().TokenCanonical },
		func(c *WorkloadContract) { c.TokenDevice = 1 },
		func(c *WorkloadContract) { c.TokenInode = 2 },
		func(c *WorkloadContract) { c.Image = "mutable:latest" },
		func(c *WorkloadContract) { c.ProtectedInode = 0 },
	} {
		c := portable()
		change(c)
		if ValidateWorkloadContract(c) == nil {
			t.Fatal("unsafe portable declaration accepted")
		}
	}
	legacy, _ := json.Marshal(workloadDeclaration())
	for _, field := range []string{`"provider":""`, `"identity_mode":null`, `"agent_uid":0`, `"agent_gid":null`, `"AGENT_UID":0`} {
		mixed := append(append([]byte{}, legacy[:len(legacy)-1]...), []byte(","+field+"}")...)
		var c WorkloadContract
		if json.Unmarshal(mixed, &c) == nil {
			t.Fatalf("accepted mixed schema: %s", field)
		}
	}
	for _, c := range []*WorkloadContract{workloadDeclaration(), portable()} {
		raw, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		var roundtrip WorkloadContract
		if err := json.Unmarshal(raw, &roundtrip); err != nil || roundtrip != *c {
			t.Fatalf("contract roundtrip changed: %v", err)
		}
	}
}

func TestNativeSnapshotDeclaration(t *testing.T) {
	c := workloadDeclaration()
	c.Schema = "sandprobe.workload-contract/2"
	c.Provider = "daytona"
	c.IdentityMode = "host_controller_no_guest_credentials"
	c.AgentUID, c.AgentGID = 10001, 10001
	c.TokenCanonical, c.TokenDevice, c.TokenInode = "", 0, 0
	c.Image = ""
	c.SnapshotID = "12345678-1234-1234-1234-123456789abc"
	if err := ValidateWorkloadContract(c); err != nil {
		t.Fatal(err)
	}
	c.ImageContentVerified = true
	if ValidateWorkloadContract(c) == nil {
		t.Fatal("snapshot mistaken for digest")
	}
	c.ImageContentVerified = false
	c.SnapshotID = "mutable-tag"
	if ValidateWorkloadContract(c) == nil {
		t.Fatal("mutable snapshot accepted")
	}
}
