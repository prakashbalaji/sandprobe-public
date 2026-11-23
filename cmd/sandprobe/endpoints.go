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
// destinations they add, and the checks still off. existing is run exec's box, where AMP-6 never connects (PRV-1);
// noCanary is HCN-5's -no-canary, under which EGR-3, a canary check, never runs and so names no proxy.
func attestedPlan(attested []string, off map[string]string, existing, noCanary bool, rule string) (lines, contacts, named []string) {
	for _, id := range slices.Sorted(slices.Values(attested)) {
		line := id + " (" + endpointNames[id] + "): you attest your provider's terms allow it on your own account"
		if id == "AMP-6" && existing {
			line += "; it still won't run, since an existing box gets no vsock connects (PRV-1)"
		}
		if id == "EGR-3" && noCanary {
			line += "; it still won't run, since it carries its nonce to a canary and -no-canary names none (HCN-5)"
		}
		lines = append(lines, line)
	}
	if slices.Contains(attested, "SEC-4") {
		contacts = append(contacts, metadataContacts()...)
	}
	if slices.Contains(attested, "AMP-7") {
		named = append(named, "a Kubernetes API, only if the box's environment names one: a TCP and TLS handshake, no request (AMP-7)")
	}
	if slices.Contains(attested, "EGR-3") && !noCanary {
		named = append(named, "the proxy the box's environment names, only to carry this run's nonce to the canary (EGR-3)")
	}
	if left := slices.Sorted(maps.Keys(lift(off, attested))); len(left) > 0 {
		named = append(named, "nothing else: "+strings.Join(left, ", ")+" stay off, since they'd contact your provider's own endpoints ("+rule+")")
	}
	return lines, contacts, named
}

// metadataContacts is SEC-4's fixed addresses for a plan (UX-4): one line each, with its port, its condition and what
// is sent, from the catalog list the probe itself dials, so the plan and the probe can't disagree.
func metadataContacts() []string {
	var out []string
	for _, d := range catalog.Metadata {
		line := d.Addr + ", " + d.What
		if d.When != "" {
			line += ", " + d.When
		}
		out = append(out, line+": "+d.How+" (SEC-4)")
	}
	return out
}

// noCanaryLine is HCN-5's plan line for -no-canary: no test traffic goes to any canary, and each connection the
// checks turned on with -provider-endpoints still make is named (PRV-15): SEC-4's addresses from the catalog list the
// probe dials (UX-4), AMP-7's handshake, and AMP-6's vsock connects on a box the run created. EGR-3 needs a canary, so
// it makes none. existing is run exec's box, where AMP-6 never connects (PRV-1).
func noCanaryLine(attested []string, existing bool) string {
	line := "none: you chose -no-canary, so the probe sends no test traffic to any canary, and the exfiltration checks aren't tested (the run can't grade above C)"
	var still []string
	for _, id := range slices.Sorted(slices.Values(attested)) {
		switch {
		case id == "SEC-4":
			var addrs []string
			for _, d := range catalog.Metadata {
				addrs = append(addrs, d.Addr)
			}
			still = append(still, "SEC-4 to the metadata addresses "+strings.Join(addrs, ", ")+", each listed here")
		case id == "AMP-6" && !existing:
			still = append(still, "AMP-6's vsock connects to the host, if the box has a vsock device")
		case id == "AMP-7":
			still = append(still, "AMP-7's TCP and TLS handshake, with no request, to a Kubernetes API the box's environment names")
		}
	}
	if len(still) > 0 {
		line += ". The checks you turned on with -provider-endpoints still make their own connections: " + strings.Join(still, "; ")
	}
	return line
}

// localProxy is a plan's local-proxy line once the person may have turned EGR-3 on (PRV-15, SBX-1 (e)).
func localProxy(attested []string, allow, noCanary bool) string {
	switch {
	case !slices.Contains(attested, "EGR-3"):
		return "excluded: EGR-3 is off"
	case noCanary:
		return "excluded: EGR-3 needs a canary, and -no-canary names none (HCN-5)"
	case allow:
		return "yes: you approved -allow-local-proxy, so EGR-3 may use a proxy on the box's own loopback"
	}
	return "no: a proxy on the box's own loopback is contacted only with -allow-local-proxy"
}
