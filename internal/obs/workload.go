package obs

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"sandprobe/internal/strictjson"
)

const WorkloadProfile = "networked-coding-v1"
const ProtectedMarker = "/opt/sandprobe/protected-marker"
const IdentityToken = "/var/run/secrets/pods.eks.amazonaws.com/serviceaccount/eks-pod-identity-token"

// WorkloadContract is WGR-1's pre-workload host declaration. Verification flags
// describe host configuration checks, never attestation of guest measurements.
// Scalars allow immutable copying into the manifest.
type WorkloadContract struct {
	ReceiverBindingSHA256 string `json:"receiver_binding_sha256,omitempty"` // MEAS-1: common host-only pre-workload declaration
	AgentHomeSHA256       string `json:"agent_home_sha256,omitempty"`       // RUN-15: owned-home metadata, not provider isolation evidence
	// WGR-7: version2 freezes the actual non-root principal without an EKS token.
	Provider                      string `json:"provider,omitempty"`
	IdentityMode                  string `json:"identity_mode,omitempty"`
	AgentUID                      int    `json:"agent_uid,omitempty"`
	AgentGID                      int    `json:"agent_gid,omitempty"`
	SnapshotID                    string `json:"snapshot_id,omitempty"`
	ImageContentVerified          bool   `json:"image_content_verified,omitempty"`
	ProtectedDevice               uint64 `json:"protected_device"`
	ProtectedInode                uint64 `json:"protected_inode"`
	Schema                        string `json:"schema"`
	Profile                       string `json:"profile"`
	ManagedRunID                  string `json:"managed_run_id"`
	BoxID                         string `json:"box_id"`
	Image                         string `json:"image"`
	ConfigSHA256                  string `json:"config_sha256"`
	IdentityPolicySHA256          string `json:"identity_policy_sha256"`
	TokenCanonical                string `json:"token_canonical"`
	TokenDevice                   uint64 `json:"token_device"`
	TokenInode                    uint64 `json:"token_inode"`
	PrivateContainerVerified      bool   `json:"private_container_verified"`
	IdentityConfigurationVerified bool   `json:"identity_configuration_verified"`
	ProtectedFixtureVerified      bool   `json:"protected_fixture_verified"`
}

var workloadHex = regexp.MustCompile(`^[a-f0-9]{64}$`)
var workloadImage = regexp.MustCompile(`^[a-z0-9][a-z0-9._:/-]{1,380}@sha256:[a-f0-9]{64}$`)
var workloadRun = regexp.MustCompile(`^[a-f0-9]{16}$`)
var workloadSnapshot = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
var workloadTokenCanonical = regexp.MustCompile(`^/run/secrets/pods\.eks\.amazonaws\.com/serviceaccount/\.\.[0-9_.]+/eks-pod-identity-token$`)

// WGR-7: reject mixed wire schemas even when a v2-only field is null/zero.
// Decode into an alias to retain strict framing without recursively invoking us.
func (c *WorkloadContract) UnmarshalJSON(raw []byte) error {
	type wireContract WorkloadContract
	var wire wireContract
	if err := strictjson.Decode(raw, 16384, &wire); err != nil {
		return err
	}
	if wire.Schema == "sandprobe.workload-contract/1" {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			return err
		}
		for name := range fields {
			for _, reserved := range []string{"provider", "identity_mode", "agent_uid", "agent_gid", "snapshot_id", "image_content_verified"} {
				if strings.EqualFold(name, reserved) {
					return errors.New("portable identity field in Nitro workload contract")
				}
			}
		}
	}
	*c = WorkloadContract(wire)
	return nil
}

func ValidateWorkloadContract(c *WorkloadContract) error {
	if c == nil {
		return nil
	}
	if c.ReceiverBindingSHA256 != "" && !workloadHex.MatchString(c.ReceiverBindingSHA256) {
		return errors.New("invalid receiver declaration hash")
	}
	if c.AgentHomeSHA256 != "" && !workloadHex.MatchString(c.AgentHomeSHA256) {
		return errors.New("invalid workload home declaration hash")
	}
	if c.Profile != WorkloadProfile || !workloadRun.MatchString(c.ManagedRunID) ||
		c.BoxID == "" || len(c.BoxID) > 128 || !workloadHex.MatchString(c.ConfigSHA256) || !workloadHex.MatchString(c.IdentityPolicySHA256) ||
		c.ProtectedDevice == 0 || c.ProtectedInode == 0 {
		return errors.New("invalid workload contract")
	}
	switch c.Schema {
	case "sandprobe.workload-contract/1":
		if c.Provider != "" || c.IdentityMode != "" || c.AgentUID != 0 || c.AgentGID != 0 ||
			c.SnapshotID != "" || c.ImageContentVerified || !workloadImage.MatchString(c.Image) ||
			!workloadTokenCanonical.MatchString(c.TokenCanonical) || c.TokenDevice == 0 || c.TokenInode == 0 {
			return errors.New("invalid Nitro workload identity contract")
		}
	case "sandprobe.workload-contract/2":
		if c.Provider != "daytona" || c.IdentityMode != "host_controller_no_guest_credentials" ||
			c.AgentUID <= 0 || uint64(c.AgentUID) >= 1<<32-1 || c.AgentGID <= 0 || uint64(c.AgentGID) >= 1<<32-1 ||
			c.TokenCanonical != "" || c.TokenDevice != 0 || c.TokenInode != 0 {
			return errors.New("invalid portable workload identity contract")
		}
		if c.SnapshotID != "" && !workloadSnapshot.MatchString(c.SnapshotID) {
			return errors.New("invalid snapshot identity")
		}
		if c.Image == "" {
			if c.SnapshotID == "" || c.ImageContentVerified {
				return errors.New("missing or falsely verified image binding")
			}
		} else if !workloadImage.MatchString(c.Image) {
			return errors.New("invalid image binding")
		}
	default:
		return errors.New("unsupported workload contract schema")
	}
	return nil
}
