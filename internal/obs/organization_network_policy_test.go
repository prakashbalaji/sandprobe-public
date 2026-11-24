package obs

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestOrganizationNetworkPolicyKeepsUnknownDistinctFromFalse(t *testing.T) {
	base := UnknownOrganizationNetworkPolicy(strings.Repeat("a", 16), "fixture-box", strings.Repeat("b", 64))
	if ValidateOrganizationNetworkPolicy(base) != nil {
		t.Fatal("unknown rejected")
	}
	wire, _ := json.Marshal(base)
	if strings.Contains(string(wire), "limited_network_egress") {
		t.Fatal("unknown encoded as false")
	}
	actualFalse := false
	observed := base
	observed.Result, observed.Reason, observed.LimitedNetworkEgress = "observed", "matching_organization_readback", &actualFalse
	if ValidateOrganizationNetworkPolicy(observed) != nil {
		t.Fatal("observed false rejected")
	}
	wire, _ = json.Marshal(observed)
	if !strings.Contains(string(wire), `"limited_network_egress":false`) {
		t.Fatal("observed false omitted")
	}
	for _, change := range []func(*OrganizationNetworkPolicyEvidence){
		func(e *OrganizationNetworkPolicyEvidence) { e.EnforcementObserved = true },
		func(e *OrganizationNetworkPolicyEvidence) { e.Result = "pass" },
		func(e *OrganizationNetworkPolicyEvidence) { e.LimitedNetworkEgress = nil },
		func(e *OrganizationNetworkPolicyEvidence) { e.Scope = "effective_policy" },
		func(e *OrganizationNetworkPolicyEvidence) { e.Reason = "raw provider message" },
	} {
		bad := observed
		change(&bad)
		if ValidateOrganizationNetworkPolicy(bad) == nil {
			t.Fatal("unsafe evidence accepted")
		}
	}
	base.LimitedNetworkEgress = &actualFalse
	if ValidateOrganizationNetworkPolicy(base) == nil {
		t.Fatal("unknown gained policy value")
	}
}
