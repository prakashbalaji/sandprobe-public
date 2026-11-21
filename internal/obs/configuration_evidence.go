package obs

import (
	"errors"
	"strings"
)

const ConfigurationEvidenceSchema = "sandprobe.configuration-evidence/1"

// EVD-5: these are host-collected configuration readbacks, never attestation or
// guest assertions. They do not independently grant a grading pass.
type ConfigurationEvidence struct {
	Schema       string                       `json:"schema"`
	ManagedRunID string                       `json:"managed_run_id"`
	BoxID        string                       `json:"box_id"`
	ConfigSHA256 string                       `json:"config_sha256"`
	Assurance    string                       `json:"assurance"`
	Image        ImageConfigurationEvidence   `json:"image"`
	Process      ProcessConfigurationEvidence `json:"process"`
}
type ImageConfigurationEvidence struct {
	Result    string `json:"result"`
	Source    string `json:"source"`
	Reason    string `json:"reason"`
	Requested string `json:"requested,omitempty"`
	Observed  string `json:"observed,omitempty"`
}
type ProcessConfigurationEvidence struct {
	Result string `json:"result"`
	Source string `json:"source"`
	Reason string `json:"reason"`
}

// RuntimeImageDigest accepts only complete supported runtime identities, not an
// embedded digest in an arbitrary status string. Mirrored by configuration_evidence.py.
func RuntimeImageDigest(value string) string {
	for _, prefix := range []string{"docker-pullable://", "containerd://", "docker://"} {
		if strings.HasPrefix(value, prefix) {
			value = strings.TrimPrefix(value, prefix)
			break
		}
	}
	if strings.Contains(value, "://") {
		return ""
	}
	if strings.HasPrefix(value, "sha256:") && workloadHex.MatchString(strings.TrimPrefix(value, "sha256:")) {
		return value
	}
	if workloadImage.MatchString(value) {
		return strings.SplitN(value, "@", 2)[1]
	}
	return ""
}

func ValidateConfigurationEvidence(e ConfigurationEvidence) error {
	bad := errors.New("invalid configuration evidence")
	if e.Schema != ConfigurationEvidenceSchema || !workloadRun.MatchString(e.ManagedRunID) || e.BoxID == "" || len(e.BoxID) > 128 || !workloadHex.MatchString(e.ConfigSHA256) || e.Assurance != "configuration_readback_not_attestation" {
		return bad
	}
	i := e.Image
	switch i.Result {
	case "verified":
		if i.Source != "control_plane_runtime_status" || i.Reason != "exact_digest_match" || !workloadImage.MatchString(i.Requested) || strings.Contains(i.Requested, "://") || RuntimeImageDigest(i.Observed) == "" || RuntimeImageDigest(i.Observed) != RuntimeImageDigest(i.Requested) {
			return bad
		}
	case "unknown":
		if i.Source != "snapshot_metadata" || i.Reason != "runtime_digest_unavailable" || i.Requested != "" || i.Observed != "" {
			return bad
		}
	default:
		return bad
	}
	p := e.Process
	if !(p.Result == "verified" && p.Source == "control_plane_spec" && p.Reason == "private_container_guards_passed") && !(p.Result == "unknown" && p.Source == "not_available" && p.Reason == "isolation_readback_unavailable") {
		return bad
	}
	return nil
}

// UnavailableConfigurationEvidence does not promote snapshot metadata or API
// visibility to runtime image/private-container verification.
func UnavailableConfigurationEvidence(run, box, configHash string) ConfigurationEvidence {
	return ConfigurationEvidence{Schema: ConfigurationEvidenceSchema, ManagedRunID: run, BoxID: box, ConfigSHA256: configHash, Assurance: "configuration_readback_not_attestation", Image: ImageConfigurationEvidence{Result: "unknown", Source: "snapshot_metadata", Reason: "runtime_digest_unavailable"}, Process: ProcessConfigurationEvidence{Result: "unknown", Source: "not_available", Reason: "isolation_readback_unavailable"}}
}
