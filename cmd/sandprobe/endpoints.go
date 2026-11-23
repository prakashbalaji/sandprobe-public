package main

import (
	"maps"
	"slices"
	"strings"

	"sandprobe/internal/catalog"
)

// providerEndpoints reads PRV-15's -provider-endpoints: the provider-endpoint checks the person attests their
// provider's terms allow on their own account, each named once as the catalog spells it, and each one of the run's
// exclusions (off). Nothing selects them all at once, and a value that isn't a check is never echoed.
func providerEndpoints(value string, set bool, off map[string]string) ([]string, error) {
	if !set {
		return nil, nil
	}
	fix := "name each check your provider's terms allow on your own account, for example -provider-endpoints SEC-4,AMP-7"
	if strings.TrimSpace(value) == "" {
		return nil, fail("usage", "-provider-endpoints needs the checks you attest your provider's terms allow (PRV-15)", fix, exitUsage)
	}
	var ids []string
	for _, id := range strings.Split(value, ",") {
		id = strings.TrimSpace(id)
		switch {
		case strings.EqualFold(id, "all") || id == "*":
			return nil, fail("usage", "-provider-endpoints never selects them all at once: name each check (PRV-15)", fix, exitUsage)
		case !catalog.ProviderEndpoints[id]:
			return nil, fail("usage", "-provider-endpoints takes only SEC-4, EGR-3, AMP-6 and AMP-7, comma-separated (PRV-15)", fix, exitUsage)
		case slices.Contains(ids, id):
			return nil, fail("usage", "-provider-endpoints names "+id+" twice", fix, exitUsage)
		case off[id] == "":
			return nil, fail("usage", id+" isn't off for this run, so there's nothing to turn on (RCP-4)", fix, exitUsage)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// lift is the run's exclusions without the checks the person attested (PRV-15): those leave it, the rest stay opt-in.
func lift(excluded map[string]string, attested []string) map[string]string {
	out := maps.Clone(excluded)
	for _, id := range attested {
		delete(out, id)
	}
	return out
}

// endpointNames are the provider-endpoint checks in plain words, for the plan.
var endpointNames = map[string]string{"SEC-4": "cloud metadata credentials", "EGR-3": "HTTPS through the box's proxy",
	"AMP-6": "vsock to the host", "AMP-7": "the Kubernetes API"}

// attestedPlan is what a plan says for PRV-15's attestations, before approval (AGT-3): each attested check, the
// destinations they add, and the checks still off. existing is run exec's box, where AMP-6 never connects (PRV-1).
func attestedPlan(attested []string, off map[string]string, existing bool, rule string) (lines, contacts, named []string) {
	for _, id := range slices.Sorted(slices.Values(attested)) {
		line := id + " (" + endpointNames[id] + "): you attest your provider's terms allow it on your own account"
		if id == "AMP-6" && existing {
			line += "; it still won't run, since an existing box gets no vsock connects (PRV-1)"
		}
		lines = append(lines, line)
	}
	if slices.Contains(attested, "SEC-4") {
		contacts = append(contacts, "the cloud metadata address 169.254.169.254, and the ECS or EKS credential endpoints only if the box's environment names them: role listings only, never a credential (SEC-4)")
	}
	if slices.Contains(attested, "AMP-7") {
		named = append(named, "a Kubernetes API, only if the box's environment names one: a TCP and TLS handshake, no request (AMP-7)")
	}
	if slices.Contains(attested, "EGR-3") {
		named = append(named, "the proxy the box's environment names, only to carry this run's nonce to the canary (EGR-3)")
	}
	if left := slices.Sorted(maps.Keys(lift(off, attested))); len(left) > 0 {
		named = append(named, "nothing else: "+strings.Join(left, ", ")+" stay off, since they'd contact your provider's own endpoints ("+rule+")")
	}
	return lines, contacts, named
}

// localProxy is a plan's local-proxy line once the person may have turned EGR-3 on (PRV-15, SBX-1 (e)).
func localProxy(attested []string, allow bool) string {
	switch {
	case !slices.Contains(attested, "EGR-3"):
		return "excluded: EGR-3 is off"
	case allow:
		return "yes: you approved -allow-local-proxy, so EGR-3 may use a proxy on the box's own loopback"
	}
	return "no: a proxy on the box's own loopback is contacted only with -allow-local-proxy"
}
