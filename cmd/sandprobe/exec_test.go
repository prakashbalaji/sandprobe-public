package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"sandprobe/internal/host"
)

var testPin = strings.Repeat("ab", 32)

func TestExecBlockDevicePaths(t *testing.T) {
	t.Setenv("SANDPROBE_CANARY", "")
	t.Setenv("SANDPROBE_CANARY_URL", "")
	t.Setenv("SANDPROBE_CANARY_PIN", "")
	var out, errs bytes.Buffer
	code := run([]string{"plan", "exec", "-o", "json", "-no-canary", "-block-device-path", "/dev/workload/disk", "-block-device-path", "/mounted-device", "--", "sh"}, &out, &errs)
	if code != 0 || !strings.Contains(out.String(), "/dev/workload/disk") || !strings.Contains(out.String(), "/mounted-device") || !strings.Contains(out.String(), "never opened for I/O") {
		t.Fatalf("declarations missing from plan: %d %s %s", code, out.String(), errs.String())
	}
	for _, args := range [][]string{
		{"plan", "exec", "-block-device-path", "relative", "--", "sh"},
		{"plan", "exec", "-block-device-path", "/dev/disk", "-block-device-path", "/dev/disk", "--", "sh"},
		{"plan", "sprites", "-block-device-path", "/dev/disk"},
	} {
		out.Reset()
		errs.Reset()
		if code := run(args, &out, &errs); code != exitUsage {
			t.Fatalf("invalid declaration accepted: exit %d", code)
		}
	}
}

// PRV-15 and HCN-5 at the command line: what run exec refuses before anything runs.
func TestRunExecRefusals(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // no operator canary state
	t.Setenv("SANDPROBE_CANARY", "")
	t.Setenv("SANDPROBE_CANARY_URL", "")
	t.Setenv("SANDPROBE_CANARY_PIN", "")
	for _, tc := range []struct {
		args []string
		code int
		says string
	}{
		{[]string{"run", "exec", "-y"}, exitUsage, "after --"},
		{[]string{"plan", "sprites", "--", "sh"}, exitUsage, "run exec"},
		{[]string{"plan", "exec", "-scratch", "relative", "--", "sh"}, exitUsage, "-scratch"},
		{[]string{"plan", "exec", "-as", "Bad;name", "--", "sh"}, exitUsage, "-as"},
		{[]string{"plan", "exec", "--", "no-such-command-sandprobe"}, exitUsage, "PATH"},
		{[]string{"plan", "exec", "-canary-url", "https://control.sandprobe.test", "--", "sh"}, exitUsage, "-canary-pin"},
	} {
		var out, errs bytes.Buffer
		code := run(tc.args, &out, &errs)
		if code != tc.code || !strings.Contains(out.String()+errs.String(), tc.says) {
			t.Errorf("%q: exit %d (want %d), %q", tc.args, code, tc.code, out.String()+errs.String())
		}
	}
}

// The plan names the box, the scratch path, the canary and its retention, and contacts no provider endpoint.
func TestRunExecPlan(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	var out, errs bytes.Buffer
	code := run([]string{"plan", "exec", "-o", "json", "-as", "agent", "-canary-url", "https://control.sandprobe.test", "-canary-pin", testPin,
		"--", "sh", "-c", "exec sh"}, &out, &errs)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs.String())
	}
	var p planDoc
	if err := json.Unmarshal(out.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	if p.Provider != "exec" {
		t.Errorf("provider %q", p.Provider)
	}
	for _, want := range []string{"/tmp/sandprobe-", "sh -c exec sh", "as agent, checked before any check runs", "uname -m",
		"control.sandprobe.test", "at most 30 minutes", "SEC-4, EGR-3, AMP-6 and AMP-7 are off", "PER-5 is skipped", "nothing of your box"} {
		if !strings.Contains(text, want) {
			t.Errorf("the plan doesn't say %q", want)
		}
	}
	if strings.Contains(text, "169.254.") {
		t.Error("the plan names a metadata address")
	}
}

// AGT-3: without -y outside a terminal, nothing runs and the plan is shown for approval.
func TestRunExecNeedsApproval(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	var out, errs bytes.Buffer
	code := run([]string{"run", "exec", "-o", "json", "-canary-url", "https://control.sandprobe.test", "-canary-pin", testPin, "--", "sh"}, &out, &errs)
	var p planDoc
	if code != exitApproval || json.Unmarshal(out.Bytes(), &p) != nil || !p.NeedsApproval {
		t.Fatalf("exit %d: %s %s", code, out.String(), errs.String())
	}
}

func TestValidExecUser(t *testing.T) {
	for _, ok := range []string{"agent", "_svc", "a.b-c", "1000", "0"} {
		if !validExecUser(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", "Agent", "a;b", "-a", ".a", strings.Repeat("a", 33), "1a"} {
		if validExecUser(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

// The plan may be shared, so a URL or pin pasted with a credential in it never reaches it, in text or JSON: run exec
// checks both before building the plan, and its errors never repeat them.
func TestRunExecPlanNeverEchoesPastedSecrets(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	for _, tc := range [][]string{
		{"-canary-url", "https://user:hunter2@control.sandprobe.test", "-canary-pin", testPin},
		{"-canary-url", "https://control.sandprobe.test/?token=hunter2", "-canary-pin", testPin},
		{"-canary-url", "https://control.sandprobe.test/#hunter2", "-canary-pin", testPin},
		{"-canary-url", "https://control.sandprobe.test/hunter2", "-canary-pin", testPin},
		{"-canary-url", "https://control.sandprobe.test", "-canary-pin", "hunter2"},
		{"-canary-url", "https://control.sandprobe.test", "-canary-pin", testPin + ",hunter2"},
	} {
		for _, format := range []string{"text", "json"} {
			var out, errs bytes.Buffer
			args := append(append([]string{"plan", "exec", "-o", format}, tc...), "--", "sh")
			if code := run(args, &out, &errs); code != exitUsage || strings.Contains(out.String()+errs.String(), "hunter2") {
				t.Errorf("%q (%s): exit %d, %q", tc, format, code, out.String()+errs.String())
			}
		}
	}
	var out, errs bytes.Buffer
	code := run([]string{"plan", "exec", "-canary-url", "HTTPS://Control.Sandprobe.Test", "-canary-pin", strings.ToUpper(testPin), "--", "sh"}, &out, &errs)
	if code != 0 || !strings.Contains(out.String(), "https://control.sandprobe.test") || !strings.Contains(out.String(), testPin[:12]) {
		t.Fatalf("the canonical URL and pin aren't in the plan: exit %d, %s %s", code, out.String(), errs.String())
	}
}

// HCN-7: canary check keeps HCN-5's refusals, each before any canary is asked. None of these reaches a network.
func TestCanaryCheckRefusals(t *testing.T) {
	for _, tc := range []struct {
		args   []string
		envPin string
		says   string
	}{
		{[]string{"canary"}, "", "canary takes check"},
		{[]string{"canary", "check", "-canary-url", "https://control.sandprobe.test"}, "", "-canary-url needs -canary-pin"},
		{[]string{"canary", "check", "-canary-pin", testPin}, "", "needs -canary-url"},
		{[]string{"canary", "check"}, testPin, "needs -canary-url"},
		{[]string{"plan", "exec", "-tls-insecure", "--", "sh"}, "", "only to canary check"},
		{[]string{"canary", "check", "-canary-url", "http://control.sandprobe.test", "-canary-pin", testPin}, "", "https://control.<domain>"},
	} {
		isolateCanary(t)
		t.Setenv("SANDPROBE_CANARY_PIN", tc.envPin)
		var out, errs bytes.Buffer
		if code := run(tc.args, &out, &errs); code != exitUsage || !strings.Contains(out.String()+errs.String(), tc.says) {
			t.Errorf("%q (pin in the environment %q): exit %d, %q", tc.args, tc.envPin, code, out.String()+errs.String())
		}
	}
}

// HCN-5: with no canary named, even beside a stray operator state file, run exec uses the hosted canary under the
// pinned key, and says who runs it and what it keeps.
func TestRunExecDefaultsToTheHostedCanary(t *testing.T) {
	stray := strayState(t)
	var out, errs bytes.Buffer
	if code := run([]string{"plan", "exec", "--", "sh"}, &out, &errs); code != 0 {
		t.Fatalf("exit %d: %s", code, errs.String())
	}
	for _, want := range []string{"hosted canary at https://control.pub.probe.ac0.dev", "run by Summation", "at most 30 minutes"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the plan doesn't say %q", want)
		}
	}
	if strings.Contains(out.String(), stray) || strings.Contains(out.String(), strayIP) {
		t.Errorf("the plan names the stray state file: %s", out.String())
	}
	if _, _, pins, err := host.CheckCanaryURL(hostedCanaryURL, hostedCanaryPins); err != nil || len(pins) != 1 {
		t.Fatalf("the hosted canary's URL or pin isn't valid: %v", err)
	}
}

// A pin is trust in a particular canary: given without its URL, run exec refuses rather than fall back to another.
// The test never runs a box or calls a canary, even if the guard regresses: it asks the chooser directly, and through
// plan, which only describes.
func TestRunExecPinWithoutURLIsRefused(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SANDPROBE_CANARY", "")
	t.Setenv("SANDPROBE_CANARY_URL", "")
	if c, err := (runFlags{canaryPin: testPin}).chooseCanary(); err == nil {
		t.Fatalf("the chooser set the pin aside for %q", c.url)
	}
	for _, viaEnv := range []bool{false, true} {
		args := []string{"plan", "exec", "-o", "json"}
		if viaEnv {
			t.Setenv("SANDPROBE_CANARY_PIN", testPin)
		} else {
			t.Setenv("SANDPROBE_CANARY_PIN", "")
			args = append(args, "-canary-pin", testPin)
		}
		var out, errs bytes.Buffer
		code := run(append(args, "--", "sh"), &out, &errs)
		if code != exitUsage || !strings.Contains(out.String()+errs.String(), "needs -canary-url") || strings.Contains(out.String(), "hosted canary") {
			t.Errorf("env %v: exit %d, %s %s", viaEnv, code, out.String(), errs.String())
		}
	}
}

// HCN-5 at the command line: -no-canary names no canary in the plan, never combines with one, and belongs to run exec
// only. Plan and the chooser only: nothing runs and no canary is asked, even if a guard regresses.
func TestNoCanaryFlag(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SANDPROBE_CANARY", "")
	t.Setenv("SANDPROBE_CANARY_URL", "")
	t.Setenv("SANDPROBE_CANARY_PIN", "")
	if c, err := (runFlags{noCanary: true}).chooseCanary(); err != nil || !c.none || c.url != "" || c.state != "" {
		t.Fatalf("the chooser: %+v %v", c, err)
	}
	var out, errs bytes.Buffer
	if code := run([]string{"plan", "exec", "-no-canary", "--", "sh"}, &out, &errs); code != 0 ||
		!strings.Contains(out.String(), "you chose -no-canary") || strings.Contains(out.String(), "hosted canary") {
		t.Fatalf("plan: exit %d, %s %s", code, out.String(), errs.String())
	}
	for _, args := range [][]string{
		{"plan", "exec", "-no-canary", "-canary-url", "https://control.sandprobe.test", "-canary-pin", testPin, "--", "sh"},
		{"plan", "exec", "-no-canary", "-canary", "/nowhere.state", "--", "sh"},
		{"plan", "docker", "-no-canary", "img"},
		{"plan", "sprites", "-no-canary"},
	} {
		out.Reset()
		errs.Reset()
		if code := run(args, &out, &errs); code != exitUsage {
			t.Errorf("%q: exit %d, %s %s", args, code, out.String(), errs.String())
		}
	}
}
