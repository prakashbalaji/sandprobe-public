package obs

import (
	"strings"
	"testing"
)

func validBoundary() *BoundaryContract {
	return &BoundaryContract{Schema: "sandprobe.boundary-contract/1", Workload: "aws-reference-file-v1", RequestedImage: BoundaryReferenceImage,
		ReportedImageID: "containerd://sha256:" + strings.Repeat("a", 64), AgentUID: 10001, AgentGID: 10001,
		NetworkExpectation: "unrestricted", ResetModel: "none", ProtectedResourceAttribution: "unestablished"}
}

func TestBoundaryContractValidation(t *testing.T) {
	if ValidateBoundaryContract(nil) != nil || ValidateBoundaryContract(validBoundary()) != nil {
		t.Fatal("missing or supported context rejected")
	}
	for name, edit := range map[string]func(*BoundaryContract){
		"version":            func(c *BoundaryContract) { c.Schema = "sandprobe.boundary-contract/2" },
		"workload":           func(c *BoundaryContract) { c.Workload = "provider-default" },
		"image":              func(c *BoundaryContract) { c.RequestedImage = "image:latest" },
		"missing-image-id":   func(c *BoundaryContract) { c.ReportedImageID = "" },
		"image-id-injection": func(c *BoundaryContract) { c.ReportedImageID = "\x1b[31msha256:" + strings.Repeat("a", 64) },
		"oversize-image-id":  func(c *BoundaryContract) { c.ReportedImageID = strings.Repeat("a", 257) + c.ReportedImageID },
		"uid":                func(c *BoundaryContract) { c.AgentUID = 0 },
		"gid":                func(c *BoundaryContract) { c.AgentGID = 0 },
		"network":            func(c *BoundaryContract) { c.NetworkExpectation = "all-egress-refused" },
		"reset":              func(c *BoundaryContract) { c.ResetModel = "restore" },
		"invented-role":      func(c *BoundaryContract) { c.ProtectedResourceAttribution = "verified" },
	} {
		t.Run(name, func(t *testing.T) {
			c := validBoundary()
			edit(c)
			if err := ValidateBoundaryContract(c); err == nil || err.Error() != "unsupported or malformed boundary contract" {
				t.Fatal("malformed declaration accepted or error not sanitized")
			}
		})
	}
}
