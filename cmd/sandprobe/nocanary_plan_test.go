package main

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"slices"
	"strings"
	"testing"

	"sandprobe/internal/catalog"
	"sandprobe/internal/host"
	"sandprobe/internal/obs"
)

// HCN-5 and PRV-15: under -no-canary, a plan's destinations are exactly the ones the probe can contact for the
// checks the person turned on, read from what the probe itself uses: its input as host.Plan builds it, the catalog's
// SEC-4 addresses (which TestProbeDialsTheCatalogMetadata ties to the probe's dials), and the probe's own AMP-6 code.
// The -no-canary line says no test traffic goes to any canary, and the help names only the connections that remain.
func TestNoCanaryPlanWording(t *testing.T) {
	cliKubectl(t) // a stub kubectl for run kubernetes, and HOME and the canary variables cleared
	const base = "none: you chose -no-canary, so the probe sends no test traffic to any canary, and the exfiltration checks aren't tested (the run can't grade above C)"
	// A box that names a proxy and a Kubernetes API and has a vsock device, so no survey gate closes a check.
	survey := &obs.Survey{Schema: obs.SurveySchema, KubeAPI: "10.96.0.1:443", Vsock: true,
		Proxy: &obs.ProxySetting{Var: "HTTPS_PROXY", Scheme: "http", Addr: "10.0.0.9:3128"}}
	amp6Dials := probeFuncDials(t, "amp6")
	rc, err := shippedRecipe("kubernetes")
	if err != nil {
		t.Fatal(err)
	}
	offs := map[string]map[string]string{"exec": host.ExecExclusions(), "kubernetes": recipeExclusions(rc)}
	for _, target := range []string{"exec", "kubernetes"} {
		for _, endpoints := range []string{"", "SEC-4", "AMP-7", "EGR-3", "AMP-6", "SEC-4,AMP-7", "SEC-4,EGR-3,AMP-6,AMP-7"} {
			var attested []string
			if endpoints != "" {
				attested = strings.Split(endpoints, ",")
			}
			_, in := host.Plan(host.Options{Mode: "exec", NoCanary: true, Excluded: lift(offs[target], attested),
				ExcludedKind: obs.SkipOptIn, Attested: attested, Existing: target == "exec"}, survey, "box", host.Storage{}, "", "", "")
			probes := func(id string) bool { return slices.Contains(in.Selected, id) }
			want := map[string]bool{
				"AMP-7: a TCP and TLS handshake": probes("AMP-7") && in.KubeAPI != "",
				"EGR-3: a proxy":                 probes("EGR-3") && in.Proxy != "",
				"AMP-6: vsock":                   probes("AMP-6") && amp6Dials,
			}
			for _, d := range catalog.Metadata {
				want["SEC-4: "+d.Addr] = probes("SEC-4")
			}
			p := noCanaryPlan(t, target, endpoints)
			dest := strings.Join(append(slices.Clone(p.Contacts), p.BoxNamed...), "\n")
			got := map[string]bool{
				"AMP-7: a TCP and TLS handshake": strings.Contains(dest, "TCP and TLS handshake"),
				"EGR-3: a proxy":                 strings.Contains(dest, "proxy the box's environment names"),
				"AMP-6: vsock":                   strings.Contains(dest, "vsock"),
			}
			for _, d := range catalog.Metadata {
				got["SEC-4: "+d.Addr] = strings.Contains(dest, d.Addr)
			}
			if !maps.Equal(got, want) {
				t.Errorf("%s -no-canary -provider-endpoints %q: the plan names %v, the probe can contact %v:\n%s", target, endpoints, got, want, dest)
			}
			if !strings.HasPrefix(p.Contacts[0], base) || strings.Contains(dest, "leaves the box") {
				t.Errorf("%s -no-canary %q: %q", target, endpoints, p.Contacts[0])
			}
			if slices.Contains(attested, "EGR-3") && p.LocalProxy != "excluded: EGR-3 needs a canary, and -no-canary names none (HCN-5)" {
				t.Errorf("%s -no-canary EGR-3: local proxy %q", target, p.LocalProxy)
			}
		}
	}
	var out, errs bytes.Buffer
	run([]string{"help"}, &out, &errs)
	if help := out.String(); !strings.Contains(help, "-no-canary: no test traffic goes to any canary") ||
		!strings.Contains(help, "Attested SEC-4 metadata requests and AMP-7's Kubernetes API handshake still happen") ||
		!strings.Contains(help, "EGR-3 doesn't run (HCN-5)") || strings.Contains(help, "no test traffic at all") {
		t.Errorf("the help:\n%s", help)
	}
}

// noCanaryPlan is a -no-canary plan for run exec or run kubernetes, as JSON, with -provider-endpoints when given.
func noCanaryPlan(t *testing.T, target, endpoints string) planDoc {
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
	return p
}

// probeFuncDials says whether the probe's function name calls anything that opens a connection: a dial, a connect or
// a socket. AMP-6's dials nothing today, so a plan names no vsock connection; one that starts to must be named.
func probeFuncDials(t *testing.T, name string) bool {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "../../internal/probe/amp.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var fn *ast.FuncDecl
	for _, d := range f.Decls {
		if d, ok := d.(*ast.FuncDecl); ok && d.Name.Name == name {
			fn = d
		}
	}
	if fn == nil {
		t.Fatalf("no func %s in internal/probe/amp.go", name)
	}
	dials := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			callee := ""
			switch f := call.Fun.(type) {
			case *ast.Ident:
				callee = f.Name
			case *ast.SelectorExpr:
				callee = f.Sel.Name
			}
			low := strings.ToLower(callee)
			dials = dials || strings.Contains(low, "dial") || strings.Contains(low, "connect") || strings.Contains(low, "socket")
		}
		return true
	})
	return dials
}
