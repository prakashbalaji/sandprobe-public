package obs

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestRuntimeImageIdentitySharedFixtures(t *testing.T) {
	raw, err := os.ReadFile("testdata/image-identities.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct{ Identity, Digest string }
	if err = json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		if got := RuntimeImageDigest(c.Identity); got != c.Digest {
			t.Fatalf("identity fixture mismatch: %q", c.Identity)
		}
	}
}
func TestConfigurationEvidenceSeparatesMetadataFromVerification(t *testing.T) {
	e := UnavailableConfigurationEvidence(strings.Repeat("a", 16), "original-box", strings.Repeat("b", 64))
	if err := ValidateConfigurationEvidence(e); err != nil {
		t.Fatal(err)
	}
	e.Image.Requested = "repo/image@sha256:" + strings.Repeat("c", 64)
	if ValidateConfigurationEvidence(e) == nil {
		t.Fatal("snapshot metadata promoted to verification")
	}
	e.Image = ImageConfigurationEvidence{Result: "verified", Source: "control_plane_runtime_status", Reason: "exact_digest_match", Requested: e.Image.Requested, Observed: "containerd://sha256:" + strings.Repeat("c", 64)}
	e.Process = ProcessConfigurationEvidence{Result: "verified", Source: "control_plane_spec", Reason: "private_container_guards_passed"}
	if err := ValidateConfigurationEvidence(e); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"digest", "process-source", "image-source", "hash", "run"} {
		bad := e
		switch field {
		case "digest":
			bad.Image.Observed += "suffix"
		case "process-source":
			bad.Process.Source = "guest"
		case "image-source":
			bad.Image.Source = "snapshot_metadata"
		case "hash":
			bad.ConfigSHA256 = "bad"
		case "run":
			bad.ManagedRunID = "bad"
		}
		if ValidateConfigurationEvidence(bad) == nil {
			t.Fatal("invalid evidence accepted", field)
		}
	}
}
