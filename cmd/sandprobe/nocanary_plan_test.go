package main

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"sandprobe/internal/catalog"
)

// HCN-5: a -no-canary plan says no test traffic goes to any canary, and claims nothing more. With -provider-endpoints,
// the same line names each connection the attested checks still make: SEC-4's catalog addresses (UX-4), AMP-7's
// handshake, and AMP-6's vsock connects on a recipe's box (never on run exec's existing box, PRV-1). EGR-3 needs a
// canary, so the plan says it won't run, names no proxy for it and excludes the local proxy. The help says the same.
func TestNoCanaryPlanWording(t *testing.T) {
	cliKubectl(t) // a stub kubectl for run kubernetes, and HOME and the canary variables cleared
	const base = "none: you chose -no-canary, so the probe sends no test traffic to any canary, and the exfiltration checks aren't tested (the run can't grade above C)"
	var addrs []string
	for _, d := range catalog.Metadata {
		addrs = append(addrs, d.Addr)
	}
	const still = ". The checks you turned on with -provider-endpoints still make their own connections: "
	sec4 := "SEC-4 to the metadata addresses " + strings.Join(addrs, ", ") + ", each listed here"
	const amp6 = "AMP-6's vsock connects to the host, if the box has a vsock device"
	const amp7 = "AMP-7's TCP and TLS handshake, with no request, to a Kubernetes API the box's environment names"
	const proxyNamed = "the proxy the box's environment names"
	plan := func(target string, endpoints string) (planDoc, string) {
		t.Helper()
		args := []string{"plan", target, "-no-canary", "-o", "json"}
		if endpoints != "" {
			args = append(args, "-provider-endpoints", endpoints)
		}
		if target == "exec" {
			args = append(args, "--", "sh")
		}
		var out, errs bytes.Buffer
		if code := run(args, &out, &errs); code != 0 {
			t.Fatalf("%q: exit %d, %s", args, code, errs.String())
		}
		var p planDoc
		if err := json.Unmarshal(out.Bytes(), &p); err != nil {
			t.Fatalf("%q: %v", args, err)
		}
		return p, out.String()
	}
	for _, target := range []string{"exec", "kubernetes"} {
		p, text := plan(target, "")
		if p.Contacts[0] != base || len(p.Contacts) != 1 || strings.Contains(text, "leaves the box") || strings.Contains(text, "169.254.") {
			t.Errorf("%s -no-canary: %q", target, p.Contacts)
		}
		p, _ = plan(target, "SEC-4,AMP-7")
		if want := base + still + amp7 + "; " + sec4; p.Contacts[0] != want { // in ID order
			t.Errorf("%s -no-canary SEC-4,AMP-7:\n got %q\nwant %q", target, p.Contacts[0], want)
		}
		for _, line := range sec4Lines {
			if !slices.Contains(p.Contacts, line) {
				t.Errorf("%s -no-canary SEC-4: doesn't list %q", target, line)
			}
		}
		if !slices.ContainsFunc(p.BoxNamed, func(s string) bool { return strings.Contains(s, "TCP and TLS handshake, no request (AMP-7)") }) {
			t.Errorf("%s -no-canary AMP-7: %q", target, p.BoxNamed)
		}
		p, text = plan(target, "EGR-3")
		if p.Contacts[0] != base || strings.Contains(text, proxyNamed) ||
			p.LocalProxy != "excluded: EGR-3 needs a canary, and -no-canary names none (HCN-5)" ||
			!slices.ContainsFunc(p.Attested, func(s string) bool { return strings.HasPrefix(s, "EGR-3 ") && strings.Contains(s, "still won't run") }) {
			t.Errorf("%s -no-canary EGR-3: %q %q %q %q", target, p.Contacts[0], p.Attested, p.BoxNamed, p.LocalProxy)
		}
	}
	if p, _ := plan("kubernetes", "AMP-6"); p.Contacts[0] != base+still+amp6 {
		t.Errorf("kubernetes -no-canary AMP-6: %q", p.Contacts[0])
	}
	if p, _ := plan("exec", "AMP-6"); p.Contacts[0] != base {
		t.Errorf("exec -no-canary AMP-6 names a connection an existing box never gets: %q", p.Contacts[0])
	}
	var out, errs bytes.Buffer
	run([]string{"help"}, &out, &errs)
	if help := out.String(); !strings.Contains(help, "-no-canary: no test traffic goes to any canary") ||
		!strings.Contains(help, "checks turned on with -provider-endpoints still make their own connections, which the plan names") ||
		strings.Contains(help, "no test traffic at all") {
		t.Errorf("the help:\n%s", help)
	}
}
