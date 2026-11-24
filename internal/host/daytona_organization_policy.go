package host

import (
	"context"
	"sandprobe/internal/obs"
)

// OrganizationNetworkPolicy is EVD-11's optional, host-only configuration readback.
// API/identity/schema failures remain unknown; they never become a workload failure.
func (b *DaytonaBox) OrganizationNetworkPolicy(ctx context.Context, run, configuration string) obs.OrganizationNetworkPolicyEvidence {
	e := obs.UnknownOrganizationNetworkPolicy(run, b.ID(), configuration)
	var d struct {
		Result               string `json:"result"`
		Reason               string `json:"reason"`
		LimitedNetworkEgress *bool  `json:"limited_network_egress"`
	}
	if b.gone || b.ID() == "" || b.journal.Organization == "" {
		e.Reason = "binding_unverified"
		return e
	}
	if b.call(ctx, "organization_network_policy", b.params(), &d) != nil {
		return e
	}
	e.Result, e.Reason, e.LimitedNetworkEgress = d.Result, d.Reason, d.LimitedNetworkEgress
	if obs.ValidateOrganizationNetworkPolicy(e) != nil {
		return obs.UnknownOrganizationNetworkPolicy(run, b.ID(), configuration)
	}
	return e
}
