package obs

import (
	"errors"
	"regexp"
)

// BoundaryReferenceImage is BND-1's initial reference configuration pin.
const BoundaryReferenceImage = "public.ecr.aws/amazonlinux/amazonlinux@sha256:3f018977be7a3473a0a473ed105b244b8bdec8683ecb24962f675db23017137b"

// BoundaryContract records requested host context, never evidence that a
// protected boundary held. It cannot establish any process's trust role.
// BND-1: this is not part of Input; the probe cannot declare its own policy.
type BoundaryContract struct {
	Schema                       string `json:"schema"`
	Workload                     string `json:"workload"`
	RequestedImage               string `json:"requested_image"`
	ReportedImageID              string `json:"reported_image_id"`
	AgentUID                     int    `json:"requested_agent_uid"`
	AgentGID                     int    `json:"requested_agent_gid"`
	NetworkExpectation           string `json:"network_expectation"`
	ResetModel                   string `json:"reset_model"`
	ProtectedResourceAttribution string `json:"protected_resource_attribution"`
}

var boundaryImageID = regexp.MustCompile(`^[a-zA-Z0-9._/:@-]*sha256:[0-9a-f]{64}$`)

// ValidateBoundaryContract implements BND-2. Nil is legal missing context for
// legacy/default reports. Validation is structural, never authentication.
func ValidateBoundaryContract(c *BoundaryContract) error {
	if c == nil {
		return nil
	}
	if c.Schema != "sandprobe.boundary-contract/1" || c.Workload != "aws-reference-file-v1" ||
		c.RequestedImage != BoundaryReferenceImage || len(c.ReportedImageID) > 256 || !boundaryImageID.MatchString(c.ReportedImageID) ||
		c.AgentUID != 10001 || c.AgentGID != 10001 || c.ResetModel != "none" || c.ProtectedResourceAttribution != "unestablished" ||
		(c.NetworkExpectation != "unrestricted" && c.NetworkExpectation != "deny-canary-six-routes") {
		return errors.New("unsupported or malformed boundary contract")
	}
	return nil
}
