package grade

import (
	"encoding/json"
	"strings"
	"testing"

	"sandprobe/internal/obs"
)

func workloadCase() (obs.Manifest, *obs.Doc, *obs.CanaryEvidence) {
	m, d, c := base()
	d.Identity.UID = 10001
	d.Identity.GID = 10001
	d.Identity.CapBnd = "0000000000000000"
	d.Identity.CapInh = "0000000000000000"
	d.Identity.Seccomp = 2
	m.WorkloadContract = &obs.WorkloadContract{Schema: "sandprobe.workload-contract/1", Profile: obs.WorkloadProfile, ManagedRunID: strings.Repeat("a", 16), BoxID: m.BoxID,
		Image: "registry.example/agent@sha256:" + strings.Repeat("b", 64), ConfigSHA256: strings.Repeat("c", 64), IdentityPolicySHA256: strings.Repeat("d", 64),
		TokenCanonical: "/run/secrets/pods.eks.amazonaws.com/serviceaccount/..2026_11_20_05_01/eks-pod-identity-token", TokenDevice: 1, TokenInode: 2, ProtectedDevice: 3, ProtectedInode: 4,
		PrivateContainerVerified: true, IdentityConfigurationVerified: true, ProtectedFixtureVerified: true}
	m.Targets["SEC-3"] = append(m.Targets["SEC-3"], obs.ProtectedMarker)
	o := observation(d, "SEC-3")
	o.Proof.Targets = append(o.Proof.Targets, obs.Target{Name: obs.ProtectedMarker, State: "refused", Errno: "EACCES", Device: 3, Inode: 4})
	return m, d, c
}
func runWorkload(m obs.Manifest, d *obs.Doc, c *obs.CanaryEvidence, workload string) WorkloadReport {
	b, _ := json.Marshal(d)
	return WorkloadGrade(m, b, c, workload)
}

func TestWorkloadAllowedCapabilitiesAreNotCritical(t *testing.T) {
	m, d, c := workloadCase()
	observation(d, "SEC-1").Result = obs.Finding
	observation(d, "SEC-1").Variant = "names"
	observation(d, "SEC-1").Proof = nil
	observation(d, "SEC-1").ObservedNames = []string{"GPG_KEY", "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"}
	observation(d, "SEC-2").Result = obs.Finding
	observation(d, "SEC-2").Variant = "readable"
	observation(d, "SEC-2").Proof.Targets[0].State = "found"
	observation(d, "SEC-2").Proof.Targets[0].Errno = ""
	o := observation(d, "SEC-3")
	o.Result = obs.Finding
	o.Variant = "nonempty"
	o.Proof.Discovered["run_secrets"] = 1
	o.Proof.Targets = append(o.Proof.Targets, obs.Target{Name: m.WorkloadContract.TokenCanonical, State: "found", Rule: "run_secrets", Device: 1, Inode: 2})
	c.Receipts = append(c.Receipts, obs.Receipt{Nonce: m.CheckNonces["EGR-1"], Proto: "dns", Port: 53})
	r := runWorkload(m, d, c, "reported_passed")
	if !r.Valid || !r.Complete || r.ConfigurationGrade != "B" || !r.BenchmarkRequirementsMet || r.LegacyGrade != "F" {
		t.Fatalf("%+v", r)
	}
	if r.SecurityAssurance != ConfigurationAssurance {
		t.Fatal("invented assurance")
	}
}

func TestWorkloadCalibration(t *testing.T) {
	cases := []struct {
		name     string
		change   func(obs.Manifest, *obs.Doc, *obs.CanaryEvidence)
		grade    string
		complete bool
	}{
		{"baseline", func(obs.Manifest, *obs.Doc, *obs.CanaryEvidence) {}, "B", true},
		{"missing-twin", func(m obs.Manifest, d *obs.Doc, c *obs.CanaryEvidence) { observation(d, "SEC-3").Proof.Twin = false }, "C", false},
		{"absent-marker", func(m obs.Manifest, d *obs.Doc, c *obs.CanaryEvidence) {
			o := observation(d, "SEC-3")
			for i := range o.Proof.Targets {
				if o.Proof.Targets[i].Name == obs.ProtectedMarker {
					o.Proof.Targets[i].State = "absent"
					o.Proof.Targets[i].Errno = "ENOENT"
					o.Proof.Targets[i].ParentSearchable = true
				}
			}
		}, "C", false},
		{"missing-marker-target", func(m obs.Manifest, d *obs.Doc, c *obs.CanaryEvidence) {
			o := observation(d, "SEC-3")
			o.Proof.Targets = o.Proof.Targets[:len(o.Proof.Targets)-1]
		}, "C", false},
		{"fixture-unbound", func(m obs.Manifest, d *obs.Doc, c *obs.CanaryEvidence) {
			m.WorkloadContract.ProtectedFixtureVerified = false
		}, "C", false},
		{"identity-unverified", func(m obs.Manifest, d *obs.Doc, c *obs.CanaryEvidence) {
			m.WorkloadContract.IdentityConfigurationVerified = false
		}, "C", false},
		{"unattributed-credential", func(m obs.Manifest, d *obs.Doc, c *obs.CanaryEvidence) {
			o := observation(d, "SEC-3")
			o.Result = obs.Finding
			o.Variant = "nonempty"
			o.Proof.Targets[0].State = "found"
			o.Proof.Targets[0].Errno = ""
		}, "C", false},
		{"unbound-alias", func(m obs.Manifest, d *obs.Doc, c *obs.CanaryEvidence) {
			o := observation(d, "SEC-3")
			o.Result = obs.Finding
			o.Variant = "nonempty"
			o.Proof.Discovered["run_secrets"] = 1
			o.Proof.Targets = append(o.Proof.Targets, obs.Target{Name: strings.ReplaceAll(m.WorkloadContract.TokenCanonical, "05_01", "05_02"), State: "found", Rule: "run_secrets"})
		}, "C", false},
		{"forbidden-tcp", func(m obs.Manifest, d *obs.Doc, c *obs.CanaryEvidence) {
			c.Receipts = append(c.Receipts, obs.Receipt{Nonce: m.CheckNonces["EGR-2"], Proto: "tcp", Port: 443})
		}, "D", true},
		{"protected-file", func(m obs.Manifest, d *obs.Doc, c *obs.CanaryEvidence) { exposeMarker(d) }, "D", true},
		{"combined-exposure", func(m obs.Manifest, d *obs.Doc, c *obs.CanaryEvidence) {
			exposeMarker(d)
			c.Receipts = append(c.Receipts, obs.Receipt{Nonce: m.CheckNonces["EGR-2"], Proto: "tcp", Port: 443})
		}, "F", true},
		{"combined-with-missing-context", func(m obs.Manifest, d *obs.Doc, c *obs.CanaryEvidence) {
			exposeMarker(d)
			m.WorkloadContract.PrivateContainerVerified = false
			c.Receipts = append(c.Receipts, obs.Receipt{Nonce: m.CheckNonces["EGR-2"], Proto: "tcp", Port: 443})
		}, "F", false},
		{"missing-network-controls", func(m obs.Manifest, d *obs.Doc, c *obs.CanaryEvidence) { c.Live = false }, "C", false},
		{"forged-document-binding", func(m obs.Manifest, d *obs.Doc, c *obs.CanaryEvidence) { d.BoxID = "other" }, "", false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			m, d, c := workloadCase()
			tt.change(m, d, c)
			r := runWorkload(m, d, c, "reported_passed")
			if r.ConfigurationGrade != tt.grade || r.Complete != tt.complete {
				t.Fatalf("%+v", r)
			}
			if r.ConfigurationGrade == "A" {
				t.Fatal("broad DNS earned A")
			}
		})
	}
	m, d, c := workloadCase()
	if r := runWorkload(m, d, c, "reported_failed"); r.ConfigurationGrade != "C" || r.BenchmarkRequirementsMet {
		t.Fatalf("workload failure passed: %+v", r)
	}
	m.WorkloadContract = nil
	if r := runWorkload(m, d, c, "reported_passed"); r.Valid || r.ConfigurationGrade != "" {
		t.Fatal("historical run regraded without context")
	}
}
func exposeMarker(d *obs.Doc) {
	o := observation(d, "SEC-3")
	o.Result = obs.Finding
	o.Variant = "nonempty"
	for i := range o.Proof.Targets {
		if o.Proof.Targets[i].Name == obs.ProtectedMarker {
			o.Proof.Targets[i].State = "found"
			o.Proof.Targets[i].Errno = ""
		}
	}
}

func observation(d *obs.Doc, id string) *obs.Observation {
	for i := range d.Observations {
		if d.Observations[i].ID == id {
			return &d.Observations[i]
		}
	}
	panic("missing test observation")
}

func TestWorkloadMixedProofFaultsAndIdentityBinding(t *testing.T) {
	for _, change := range []func(obs.Manifest, *obs.Doc){
		func(m obs.Manifest, d *obs.Doc) {
			o := observation(d, "SEC-3")
			o.Result = obs.Finding
			o.Variant = "nonempty"
			o.Proof.Targets[0].Errno = "EIO"
		},
		func(m obs.Manifest, d *obs.Doc) {
			o := observation(d, "SEC-3")
			o.Result = obs.Finding
			o.Variant = "nonempty"
			o.Proof.Targets[0].State = "absent"
			o.Proof.Targets[0].Errno = "ENOENT"
			o.Proof.Targets[0].ParentSearchable = false
		},
		func(m obs.Manifest, d *obs.Doc) {
			o := observation(d, "SEC-3")
			o.Result = obs.Finding
			o.Variant = "nonempty"
			o.Proof.Discovered["run_secrets"] = 1
			o.Proof.Targets = append(o.Proof.Targets, obs.Target{Name: m.WorkloadContract.TokenCanonical, State: "found", Rule: "run_secrets", Device: 1, Inode: 999})
		},
		func(m obs.Manifest, d *obs.Doc) {
			o := observation(d, "PER-1")
			o.Result = obs.Finding
			o.Variant = "writable"
			o.Proof.Targets[0].State = "found"
			o.Proof.Targets[0].Errno = ""
			o.Proof.Targets[1].Errno = "EIO"
		},
		func(m obs.Manifest, d *obs.Doc) {
			d.Identity.NoNewPrivs = ptr(0)
			d.Identity.SetuidScan = &obs.SetuidScan{Complete: true}
		},
	} {
		m, d, c := workloadCase()
		change(m, d)
		r := runWorkload(m, d, c, "reported_passed")
		if r.ConfigurationGrade != "C" || r.BenchmarkRequirementsMet {
			t.Fatalf("mixed fault accepted: %+v", r)
		}
	}
}

func TestWorkloadHostDeliverySurvivesBrokenGuestObservation(t *testing.T) {
	m, d, c := workloadCase()
	d.Nonce = "wrong"
	c.Receipts = append(c.Receipts, obs.Receipt{Nonce: m.CheckNonces["EGR-2"], Proto: "tcp", Port: 443})
	r := runWorkload(m, d, c, "reported_passed")
	if r.ConfigurationGrade != "D" || r.Complete || r.Valid || r.BenchmarkRequirementsMet {
		t.Fatalf("host delivery hidden: %+v", r)
	}
	m, d, c = workloadCase()
	d.Nonce = "wrong"
	r = runWorkload(m, d, c, "reported_passed")
	receiver := WorkloadReceiver{ExpectedUID: "owned-receiver", ObservedUID: "owned-receiver", IssuedNonces: []string{strings.Repeat("1", 48), strings.Repeat("2", 48), strings.Repeat("3", 48)}, ReceivedNonces: []string{strings.Repeat("2", 48)}}
	r = AddWorkloadReceiver(r, receiver)
	if r.ConfigurationGrade != "D" || r.Complete || r.BenchmarkRequirementsMet {
		t.Fatalf("private host delivery hidden: %+v", r)
	}
	if r.InputVerification != "retrospective_recomputation_unauthenticated_input" {
		t.Fatal("supplied records imply live authentication")
	}
}

func TestWorkloadInheritableCapabilitiesAreRequired(t *testing.T) {
	for _, tt := range []struct {
		value    string
		complete bool
	}{{"0000000000000001", true}, {"", false}, {"invalid", false}} {
		m, d, c := workloadCase()
		d.Identity.CapInh = tt.value
		r := runWorkload(m, d, c, "reported_passed")
		if r.ConfigurationGrade != "C" || r.BenchmarkRequirementsMet || r.Complete != tt.complete {
			t.Fatalf("inheritable capabilities accepted: %+v", r)
		}
	}
}

// WGR-7: shared control semantics, not an automatic second-provider pass.
func TestPortableWorkloadCalibration(t *testing.T) {
	for _, tt := range []struct {
		name     string
		change   func(obs.Manifest, *obs.Doc, *obs.CanaryEvidence)
		grade    string
		complete bool
	}{
		{"non-root-portable-baseline", func(obs.Manifest, *obs.Doc, *obs.CanaryEvidence) {}, "B", true},
		{"changed-uid", func(m obs.Manifest, d *obs.Doc, c *obs.CanaryEvidence) { d.Identity.UID++ }, "C", true},
		{"changed-gid", func(m obs.Manifest, d *obs.Doc, c *obs.CanaryEvidence) { d.Identity.GID++ }, "C", true},
		{"host-unverified", func(m obs.Manifest, d *obs.Doc, c *obs.CanaryEvidence) {
			m.WorkloadContract.IdentityConfigurationVerified = false
		}, "C", false},
		{"missing-network-proof", func(m obs.Manifest, d *obs.Doc, c *obs.CanaryEvidence) { c.Live = false }, "C", false},
		{"aws-variable-not-permitted", func(m obs.Manifest, d *obs.Doc, c *obs.CanaryEvidence) {
			o := observation(d, "SEC-1")
			o.Result = obs.Finding
			o.Variant = "names"
			o.Proof = nil
			o.ObservedNames = []string{"AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"}
		}, "C", false},
		{"eks-token-not-permitted", func(m obs.Manifest, d *obs.Doc, c *obs.CanaryEvidence) {
			o := observation(d, "SEC-3")
			o.Result = obs.Finding
			o.Variant = "nonempty"
			o.Proof.Discovered["run_secrets"] = 1
			o.Proof.Targets = append(o.Proof.Targets, obs.Target{Name: obs.IdentityToken, State: "found", Rule: "run_secrets", Device: 1, Inode: 2})
		}, "C", false},
		{"protected-resource-exposed", func(m obs.Manifest, d *obs.Doc, c *obs.CanaryEvidence) { exposeMarker(d) }, "D", true},
		{"combined-exposure", func(m obs.Manifest, d *obs.Doc, c *obs.CanaryEvidence) {
			exposeMarker(d)
			c.Receipts = append(c.Receipts, obs.Receipt{Nonce: m.CheckNonces["EGR-2"], Proto: "tcp", Port: 443})
		}, "F", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m, d, c := workloadCase()
			contract := m.WorkloadContract
			contract.Schema = "sandprobe.workload-contract/2"
			contract.ImageContentVerified = true
			contract.Provider = "daytona"
			contract.IdentityMode = "host_controller_no_guest_credentials"
			contract.AgentUID, contract.AgentGID = 1001, 1001
			contract.TokenCanonical, contract.TokenDevice, contract.TokenInode = "", 0, 0
			d.Identity.UID, d.Identity.GID = 1001, 1001
			tt.change(m, d, c)
			r := runWorkload(m, d, c, "reported_passed")
			if r.ConfigurationGrade != tt.grade || r.Complete != tt.complete || r.SecurityAssurance != ConfigurationAssurance {
				t.Fatalf("%+v", r)
			}
			if !strings.Contains(strings.Join(r.Limits, " "), "different deployment pattern") {
				t.Fatal("deployment pattern omitted")
			}
		})
	}
}

func TestNativeSnapshotCannotEarnConformance(t *testing.T) {
	m, d, c := workloadCase()
	w := m.WorkloadContract
	w.Schema = "sandprobe.workload-contract/2"
	w.Provider = "daytona"
	w.IdentityMode = "host_controller_no_guest_credentials"
	w.AgentUID, w.AgentGID = 10001, 10001
	w.TokenCanonical, w.TokenDevice, w.TokenInode = "", 0, 0
	w.Image = ""
	w.SnapshotID = "12345678-1234-1234-1234-123456789abc"
	r := runWorkload(m, d, c, "reported_passed")
	if !r.Valid || r.Complete || r.ConfigurationGrade != "C" || r.BenchmarkRequirementsMet {
		t.Fatalf("snapshot claimed image proof: %+v", r)
	}
	found := false
	for _, x := range r.Unknown {
		if x == "image-content-binding" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing explicit image coverage")
	}
}
