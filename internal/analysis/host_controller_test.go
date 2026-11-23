package analysis

import (
	"strings"
	"testing"

	"sandprobe/internal/obs"
)

// RUN-17: structural saved-report compatibility, never authentication of these fixture declarations.
func TestNitroHostControllerReportVersion(t *testing.T) {
	for _, tc := range []struct {
		schema, provider string
		ok               bool
	}{{"sandprobe/3", "aws-nitro", true}, {"sandprobe/1", "aws-nitro", false}, {"sandprobe/2", "aws-nitro", false}, {"sandprobe/3", "daytona", false}} {
		data := edited(t, func(d, m map[string]any, _ []any) {
			d["schema"] = tc.schema
			d["run"].(map[string]any)["provider"] = tc.provider
			m["workload_contract"] = &obs.WorkloadContract{Schema: "sandprobe.workload-contract/3", Profile: obs.WorkloadProfile,
				Provider: "aws-nitro", IdentityMode: "host_controller_no_guest_credentials", AgentUID: 10001, AgentGID: 10001,
				ManagedRunID: strings.Repeat("a", 16), BoxID: m["BoxID"].(string),
				Image: "registry.example/agent@sha256:" + strings.Repeat("b", 64), ImageContentVerified: true,
				ConfigSHA256: strings.Repeat("c", 64), IdentityPolicySHA256: strings.Repeat("d", 64), AgentHomeSHA256: strings.Repeat("e", 64),
				ProtectedDevice: 3, ProtectedInode: 4}
		})
		if _, err := Parse(data); (err == nil) != tc.ok {
			t.Errorf("%s %s accepted=%v, want %v", tc.schema, tc.provider, err == nil, tc.ok)
		}
	}
}
