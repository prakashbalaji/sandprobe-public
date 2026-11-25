package obs

import "errors"

const OrganizationNetworkPolicySchema = "sandprobe.organization-network-policy/1"

// EVD-11: provider configuration only. This does not prove any traffic was denied.
type OrganizationNetworkPolicyEvidence struct {
	Schema               string `json:"schema"`
	ManagedRunID         string `json:"managed_run_id"`
	BoxID                string `json:"box_id"`
	ConfigSHA256         string `json:"config_sha256"`
	Source               string `json:"source"`
	Scope                string `json:"scope"`
	Assurance            string `json:"assurance"`
	Result               string `json:"result"`
	Reason               string `json:"reason"`
	LimitedNetworkEgress *bool  `json:"limited_network_egress,omitempty"`
	EnforcementObserved  bool   `json:"enforcement_observed"`
}

func UnknownOrganizationNetworkPolicy(run, box, configuration string) OrganizationNetworkPolicyEvidence {
	return OrganizationNetworkPolicyEvidence{Schema: OrganizationNetworkPolicySchema, ManagedRunID: run, BoxID: box,
		ConfigSHA256: configuration, Source: "provider_organization_api", Scope: "organization_default",
		Assurance: "configuration_readback_not_denial_proof", Result: "unknown", Reason: "readback_unavailable"}
}
func ValidateOrganizationNetworkPolicy(e OrganizationNetworkPolicyEvidence) error {
	bad := errors.New("invalid organization network policy evidence")
	if e.Schema != OrganizationNetworkPolicySchema || !workloadRun.MatchString(e.ManagedRunID) || e.BoxID == "" || len(e.BoxID) > 128 || !workloadHex.MatchString(e.ConfigSHA256) || e.Source != "provider_organization_api" || e.Scope != "organization_default" || e.Assurance != "configuration_readback_not_denial_proof" || e.EnforcementObserved {
		return bad
	}
	if e.Result == "observed" && e.Reason == "matching_organization_readback" && e.LimitedNetworkEgress != nil {
		return nil
	}
	if e.Result != "unknown" || e.LimitedNetworkEgress != nil {
		return bad
	}
	switch e.Reason {
	case "binding_unverified", "permission_denied", "readback_unavailable", "response_mismatch",
		"authentication_failed", "endpoint_unavailable", "rate_limited", "request_rejected",
		"service_unavailable", "request_timeout", "transport_unavailable", "response_schema_invalid": // EVD-14
		return nil
	}
	return bad
}
