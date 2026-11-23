package main

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"sandprobe/internal/catalog"
	"sandprobe/internal/host"
)

// sec4Lines is what UX-4 requires every plan that runs SEC-4 to say, word for word, before approval.
var sec4Lines = []string{
	"169.254.169.254:80, AWS and GCP instance metadata: role and service-account listings only, never a credential (SEC-4)",
	"169.254.170.2:80, the ECS credential endpoint, only if the agent's environment names it (AWS_CONTAINER_CREDENTIALS_RELATIVE_URI): a connection only, no request (SEC-4)",
	"169.254.170.23:80, EKS Pod Identity, only if the agent's environment names it (AWS_CONTAINER_CREDENTIALS_FULL_URI): a connection only, no request (SEC-4)",
}

// UX-4: every plan that runs SEC-4 names each of its fixed addresses, with its port and condition, before approval:
// docker and aws-nitro always, run exec and run kubernetes once -provider-endpoints turns SEC-4 on. A plan that doesn't
// run SEC-4 names none.
func TestPlansNameEverySEC4Address(t *testing.T) {
	if got := metadataContacts(); !slices.Equal(got, sec4Lines) || len(catalog.Metadata) != len(sec4Lines) {
		t.Fatalf("the plan's SEC-4 lines:\n%s", strings.Join(got, "\n"))
	}
	choice := canaryChoice{describe: "the canary"}
	plans := map[string][]string{
		"docker":    dockerPlan("img", "root", nil).Contacts,
		"aws-nitro": nitroPlan("/k", choice, runFlags{variant: "isolated"}, host.PodSpec{Image: "i", RuntimeClass: "isolated-sandbox"}).Contacts,
	}
	var out, errs bytes.Buffer
	if code := run([]string{"plan", "exec", "-no-canary", "-provider-endpoints", "SEC-4", "-o", "json", "--", "sh"}, &out, &errs); code != 0 {
		t.Fatalf("plan exec: exit %d, %s", code, errs.String())
	}
	var p planDoc
	json.Unmarshal(out.Bytes(), &p)
	plans["exec -provider-endpoints SEC-4"] = p.Contacts
	cliKubectl(t)
	out.Reset()
	if code := run([]string{"plan", "kubernetes", "-no-canary", "-provider-endpoints", "SEC-4", "-o", "json"}, &out, &errs); code != 0 {
		t.Fatalf("plan kubernetes: exit %d, %s", code, errs.String())
	}
	p = planDoc{}
	json.Unmarshal(out.Bytes(), &p)
	plans["kubernetes -provider-endpoints SEC-4"] = p.Contacts
	for name, contacts := range plans {
		for _, want := range sec4Lines {
			if !slices.Contains(contacts, want) {
				t.Errorf("%s doesn't say %q:\n%s", name, want, strings.Join(contacts, "\n"))
			}
		}
	}
	for name, p := range map[string]planDoc{"sprites": sprPlan("org", choice, runFlags{}, ""), "e2b": e2bPlan(choice), "daytona": daytonaPlan(choice)} {
		if b, _ := json.Marshal(p); bytes.Contains(b, []byte("169.254.")) {
			t.Errorf("%s excludes SEC-4, yet its plan names a metadata address", name)
		}
	}
	out.Reset()
	run([]string{"plan", "exec", "-no-canary", "-o", "json", "--", "sh"}, &out, &errs)
	if bytes.Contains(out.Bytes(), []byte("169.254.")) {
		t.Error("run exec without SEC-4 names a metadata address")
	}
}

// UX-4: the probe dials only the catalog's SEC-4 addresses, the list every plan names: its address constants are the
// catalog's, and no other metadata address is written anywhere in the probe. A probe that gained or changed an address
// without the catalog fails here, and so would a plan that dropped one (TestPlansNameEverySEC4Address).
func TestProbeDialsTheCatalogMetadata(t *testing.T) {
	files, _ := filepath.Glob("../../internal/probe/*.go")
	consts := map[string]string{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(src, []byte("169.254.")) {
			t.Errorf("%s writes a metadata address of its own: SEC-4's come only from catalog.Metadata", f)
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), f, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(parsed, func(n ast.Node) bool {
			if vs, ok := n.(*ast.ValueSpec); ok {
				for i, name := range vs.Names {
					if i >= len(vs.Values) {
						break
					}
					if sel, ok := vs.Values[i].(*ast.SelectorExpr); ok {
						if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "catalog" && strings.HasPrefix(sel.Sel.Name, "Metadata") {
							consts[name.Name] = sel.Sel.Name
						}
					}
				}
			}
			return true
		})
	}
	want := map[string]string{"imdsAddr": "MetadataIMDS", "ecsAddr": "MetadataECS", "podIdentityAddr": "MetadataPodIdentity"}
	if len(consts) != len(want) {
		t.Errorf("the probe's metadata constants: %v", consts)
	}
	for name, sel := range want {
		if consts[name] != sel {
			t.Errorf("the probe's %s is %q, want catalog.%s", name, consts[name], sel)
		}
	}
	var addrs []string
	for _, d := range catalog.Metadata {
		addrs = append(addrs, d.Addr)
	}
	if !slices.Equal(addrs, []string{catalog.MetadataIMDS, catalog.MetadataECS, catalog.MetadataPodIdentity}) {
		t.Errorf("catalog.Metadata lists %v", addrs)
	}
}
