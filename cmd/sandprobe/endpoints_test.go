package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"sandprobe/internal/analysis"
	"sandprobe/internal/host"
	"sandprobe/internal/obs"
	"sandprobe/internal/report"
)

// PRV-15: -provider-endpoints takes only the four provider-endpoint checks, each named once and each one of the
// run's exclusions; never all at once, never empty, and a value that isn't a check is never echoed.
func TestProviderEndpointsParse(t *testing.T) {
	off := host.ExecExclusions()
	for value, want := range map[string][]string{"SEC-4,AMP-7": {"SEC-4", "AMP-7"}, " SEC-4 , AMP-7 ": {"SEC-4", "AMP-7"},
		"EGR-3": {"EGR-3"}, "SEC-4,EGR-3,AMP-6,AMP-7": {"SEC-4", "EGR-3", "AMP-6", "AMP-7"}} {
		if got, err := providerEndpoints(value, true, off); err != nil || !slices.Equal(got, want) {
			t.Errorf("%q: %v %v", value, got, err)
		}
	}
	for _, value := range []string{"", " ", "all", "ALL", "*", "SEC-4,", ",AMP-7", "sec-4", "SEC-3", "AMP-2", "SEC-4,SEC-4",
		"SEC-4,all", "SEC-4;AMP-7", "$(touch /tmp/x)"} {
		_, err := providerEndpoints(value, true, off)
		if err == nil {
			t.Errorf("%q was accepted", value)
		} else if value == "$(touch /tmp/x)" && strings.Contains(err.Error(), "touch") {
			t.Errorf("the refusal echoed the value: %v", err)
		}
	}
	if got, err := providerEndpoints("", false, off); err != nil || got != nil { // not given: nothing turned on
		t.Errorf("not given: %v %v", got, err)
	}
	if _, err := providerEndpoints("SEC-4", true, map[string]string{"AMP-7": "off"}); err == nil {
		t.Error("a check the run doesn't exclude was turned on")
	}
	if got := lift(off, []string{"SEC-4", "AMP-7"}); len(got) != 2 || got["EGR-3"] == "" || got["AMP-6"] == "" || len(off) != 4 {
		t.Errorf("lift: %v, from %v", got, off)
	}
}

// PRV-15: the flag belongs to run exec, shipped recipes and their plans only; run docker already runs these checks,
// and a provider's PRV row decides them.
func TestProviderEndpointsOnlyWhereTheyApply(t *testing.T) {
	for _, args := range [][]string{
		{"plan", "docker", "debian", "-provider-endpoints", "SEC-4"},
		{"run", "docker", "debian", "-provider-endpoints", "SEC-4", "-y"},
		{"plan", "sprites", "-provider-endpoints", "SEC-4"},
		{"run", "e2b", "-provider-endpoints", "AMP-7", "-y"},
		{"plan", "aws-nitro", "-provider-endpoints", "SEC-4"},
		{"scorecard", "../../test/reports/egress-refused.json", "-provider-endpoints", "SEC-4"},
		{"plan", "exec", "-provider-endpoints", "", "--", "sh"},
		{"plan", "exec", "-provider-endpoints", "all", "--", "sh"},
	} {
		var out, errs bytes.Buffer
		if code := run(args, &out, &errs); code != exitUsage {
			t.Errorf("%q: exit %d, want %d", args, code, exitUsage)
		}
	}
}

// PRV-15 and AGT-3: the plan lists each attested check with its attestation, the destinations it adds and the checks
// still off, before approval; an unapproved run runs nothing. AMP-6 says it still won't run on an existing box.
func TestProviderEndpointsPlan(t *testing.T) {
	var out, errs bytes.Buffer
	if code := run([]string{"plan", "exec", "-no-canary", "-provider-endpoints", "SEC-4,AMP-7", "--", "sh"}, &out, &errs); code != 0 {
		t.Fatalf("plan: exit %d, %s", code, errs.String())
	}
	for _, want := range append([]string{"Turns on, on your attestation (-provider-endpoints, PRV-15)",
		"SEC-4 (cloud metadata credentials): you attest your provider's terms allow it on your own account",
		"AMP-7 (the Kubernetes API): you attest your provider's terms allow it on your own account",
		"a TCP and TLS handshake, no request (AMP-7)",
		"nothing else: AMP-6, EGR-3 stay off", "excluded: EGR-3 is off", "You turned on SEC-4, AMP-7 with -provider-endpoints"}, sec4Lines...) {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the plan doesn't say %q:\n%s", want, out.String())
		}
	}
	out.Reset()
	// On the default canary: under -no-canary, EGR-3 never runs (HCN-5, TestNoCanaryPlanWording). A plan asks no canary.
	run([]string{"plan", "exec", "-provider-endpoints", "AMP-6,EGR-3", "-allow-local-proxy", "--", "sh"}, &out, &errs)
	if s := out.String(); !strings.Contains(s, "it still won't run, since an existing box gets no vsock connects (PRV-1)") ||
		!strings.Contains(s, "yes: you approved -allow-local-proxy") || strings.Contains(s, "169.254.169.254") {
		t.Errorf("AMP-6 and EGR-3:\n%s", s)
	}
	out.Reset()
	if code := run([]string{"run", "exec", "-no-canary", "-provider-endpoints", "SEC-4,AMP-7", "-o", "json", "--", "sh"}, &out, &errs); code != exitApproval {
		t.Fatalf("an unapproved run: exit %d", code)
	}
	var p planDoc
	if err := json.Unmarshal(out.Bytes(), &p); err != nil || !p.NeedsApproval || len(p.Attested) != 2 {
		t.Errorf("the JSON plan: %+v %v", p, err)
	}
}

// PRV-15 through RCP-4: a shipped recipe takes the flag for the checks its header excludes, and its plan and residual
// say so; nothing past sp_ready is called.
func TestProviderEndpointsRecipePlan(t *testing.T) {
	calls := cliKubectl(t)
	var out, errs bytes.Buffer
	if code := run([]string{"plan", "kubernetes", "-no-canary", "-provider-endpoints", "SEC-4,AMP-7"}, &out, &errs); code != 0 {
		t.Fatalf("plan: exit %d, %s", code, errs.String())
	}
	for _, want := range append([]string{"SEC-4 (cloud metadata credentials): you attest", "AMP-7 (the Kubernetes API): you attest",
		"nothing else: AMP-6, EGR-3 stay off, since they'd contact your provider's own endpoints (RCP-4)",
		"(EGR-3, AMP-6) were off (RCP-4)", "You turned on SEC-4, AMP-7 with -provider-endpoints"}, sec4Lines...) {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the plan doesn't say %q:\n%s", want, out.String())
		}
	}
	if c := calls(); strings.Contains(c, " run ") || strings.Contains(c, "create -f") || strings.Contains(c, "delete --raw") || strings.Contains(c, "unexpected") {
		t.Errorf("reached past sp_ready:\n%s", c)
	}
}

// PRV-15 and ANL-1: a saved report keeps the fixed attestation beside exactly the attested checks; any other
// attestation, or one missing, is refused.
func TestProviderEndpointsAttestationRecord(t *testing.T) {
	b, err := os.ReadFile("../../test/reports/egress-refused.json")
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		attested []string
		rows     map[string]string
		ok       bool
	}{
		"recorded beside the check":   {[]string{"SEC-4"}, map[string]string{"SEC-4": report.Attestation}, true},
		"beside a check not attested": {[]string{"SEC-4"}, map[string]string{"SEC-4": report.Attestation, "AMP-7": report.Attestation}, false},
		"missing from the check":      {[]string{"SEC-4"}, nil, false},
		"other words":                 {[]string{"SEC-4"}, map[string]string{"SEC-4": "the box says it's fine"}, false},
		"not a provider endpoint":     {[]string{"SEC-3"}, map[string]string{"SEC-3": report.Attestation}, false},
		"still skipped as opt-in":     {[]string{"EGR-3"}, map[string]string{"EGR-3": report.Attestation}, false},
		"on a native adapter's run":   {[]string{"SEC-4"}, map[string]string{"SEC-4": report.Attestation}, false},
		"declared sandprobe/1":        {[]string{"SEC-4"}, map[string]string{"SEC-4": report.Attestation}, false},
	} {
		var d report.Doc
		json.Unmarshal(b, &d)
		d.Run.Provider, d.Manifest.Attested = "exec", tc.attested // run exec's policy takes an attestation
		if name == "on a native adapter's run" {
			d.Run.Provider = "sprites" // SCR-2: its PRV row decides, so no attestation
		}
		if name == "still skipped as opt-in" {
			d.Manifest.SkipKinds = map[string]string{"EGR-3": obs.SkipOptIn}
		}
		for i := range d.Checks {
			d.Checks[i].Attestation = tc.rows[d.Checks[i].ID]
		}
		d.Schema = report.SchemaFor(d.Manifest) // AGT-6: each case is refused for its own rule, never its version
		if name == "declared sandprobe/1" {
			d.Schema = report.Schema // AGT-6: attestations need sandprobe/2
		}
		raw, _ := json.Marshal(d)
		if _, err := analysis.Parse(raw); (err == nil) != tc.ok {
			t.Errorf("%s: accepted %v, want %v", name, err == nil, tc.ok)
		}
	}
}

// PRV-15 end to end against a local Docker box with no network, so no cloud metadata is reachable: run exec with
// -provider-endpoints SEC-4,AMP-7 runs both, records the attestation beside each, keeps EGR-3 and AMP-6 opt-in, and
// settles Cloud access honestly: find-only results that are never a pass or an absence, listed as not proven.
func TestRunExecProviderEndpointsDocker(t *testing.T) {
	if os.Getenv("SANDPROBE_FIXTURES") == "" {
		t.Skip("set SANDPROBE_FIXTURES=1 to run against Docker")
	}
	const image = "debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2"
	id, err := exec.Command("docker", "run", "-d", "--rm", "--network", "none", "--user", "65534:65534", image, "sleep", "300").Output()
	if err != nil {
		t.Fatal(err)
	}
	ctr := strings.TrimSpace(string(id))
	defer exec.Command("docker", "rm", "-f", ctr).Run()
	dir := t.TempDir()
	var out, errs bytes.Buffer
	code := run([]string{"run", "exec", "-as", "nobody", "-no-canary", "-provider-endpoints", "SEC-4,AMP-7", "-y", "-o", "json", "-out", dir,
		"--", "docker", "exec", "-i", ctr, "sh"}, &out, &errs)
	if code != exitPartial { // HCN-5: without a canary the run is incomplete
		t.Fatalf("exit %d: %s", code, errs.String())
	}
	files, _ := filepath.Glob(filepath.Join(dir, "sandprobe-exec-*.json"))
	if len(files) != 1 {
		t.Fatalf("reports: %v", files)
	}
	d, err := analysis.Load(files[0])
	if err != nil {
		t.Fatalf("the saved report doesn't load: %v", err)
	}
	if d.Schema != report.SchemaSkipKinds || !slices.Equal(d.Manifest.Attested, []string{"AMP-7", "SEC-4"}) || len(d.Manifest.SkipKinds) != 2 ||
		d.Manifest.SkipKinds["EGR-3"] != obs.SkipOptIn || d.Manifest.SkipKinds["AMP-6"] != obs.SkipOptIn {
		t.Errorf("attested %v, kinds %v", d.Manifest.Attested, d.Manifest.SkipKinds)
	}
	for _, c := range d.Checks {
		switch c.ID {
		case "SEC-4", "AMP-7":
			if c.Result != obs.NotFound && c.Result != obs.Unknown || c.Attestation != report.Attestation {
				t.Errorf("%s: %s %q, attestation %q", c.ID, c.Result, c.Reason, c.Attestation)
			}
			t.Logf("%s: %s, %s", c.ID, c.Result, c.Evidence+c.Reason)
		case "EGR-3", "AMP-6":
			if c.Result != obs.Skipped || c.Attestation != "" {
				t.Errorf("%s: %s, attestation %q", c.ID, c.Result, c.Attestation)
			}
		}
	}
	r := report.Score(*d).Rows[4]
	if r.Name != "Cloud access" || r.NotApplicable || strings.HasPrefix(r.Why, "Not tested") || r.Green && r.NotProven == "" {
		t.Errorf("Cloud access: %+v", r)
	}
	t.Logf("Cloud access: green %v, %q %q", r.Green, r.Why, r.NotProven)
}

// HCN-5 and PRV-15: merging the canary and endpoint flags must preserve both decisions.
// Planning performs no network calls and an explicit canary choice clears stale environment defaults.
func TestProviderEndpointsWithExplicitCanary(t *testing.T) {
	isolateCanary(t)
	t.Setenv("SANDPROBE_CANARY", "/stale-canary.state")
	t.Setenv("SANDPROBE_CANARY_URL", "https://stale.example")
	t.Setenv("SANDPROBE_CANARY_PIN", "stale-pin")
	for _, args := range [][]string{
		{"plan", "exec", "-no-canary", "-provider-endpoints", "SEC-4,AMP-7", "-o", "json", "--", "sh"},
		{"plan", "exec", "-canary-url", "https://control.sandprobe.test", "-canary-pin", testPin, "-provider-endpoints", "SEC-4,AMP-7", "-o", "json", "--", "sh"},
	} {
		var out, errs bytes.Buffer
		if code := run(args, &out, &errs); code != 0 {
			t.Fatalf("plan: exit %d, %s", code, errs.String())
		}
		var p planDoc
		if err := json.Unmarshal(out.Bytes(), &p); err != nil || len(p.Attested) != 2 {
			t.Fatalf("canary selection lost attestations: %+v %v", p, err)
		}
		if strings.Contains(out.String(), "stale") {
			t.Fatal("explicit canary selection retained an environment default")
		}
	}
}
