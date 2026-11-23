package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"sandprobe/internal/canary"
	"sandprobe/internal/canarycontrol"
	"sandprobe/internal/host"
	"sandprobe/internal/obs"
)

// strayIP is the address a stray operator state file records: it must never reach a plan, a readiness line or a run.
const strayIP = "198.51.100.77"

// isolateCanary gives a test its own HOME and clears every canary variable, so nothing of the person's own canary
// setup reaches it.
func isolateCanary(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SANDPROBE_CANARY", "")
	t.Setenv("SANDPROBE_CANARY_URL", "")
	t.Setenv("SANDPROBE_CANARY_PIN", "")
}

// strayState isolates the test and leaves exactly one whole operator canary state file where deploy/canary.sh writes
// it: the case that once sent run exec to a dead operator canary. It returns the file's path.
func strayState(t *testing.T) string {
	t.Helper()
	isolateCanary(t)
	if err := os.MkdirAll(configDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(configDir(), "canary-stray-us-west-2.state")
	body := "profile=stray\nregion=us-west-2\ninstance=i-0123456789abcdef0\nip=" + strayIP + "\ndomain=stray.example\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// hostedChoice is the canary a run uses with nothing named: the hosted one.
func hostedChoice(t *testing.T) canaryChoice {
	t.Helper()
	c, err := runFlags{}.chooseCanary()
	if err != nil || c.url != hostedCanaryURL {
		t.Fatalf("no canary named: %+v %v", c, err)
	}
	return c
}

// HCN-5's precedence, with no network call: -canary (flag or SANDPROBE_CANARY) first, then -canary-url with its pin,
// then the hosted canary. A stray canary-*.state file is never chosen, and a pin without its URL is refused.
func TestCanaryPrecedence(t *testing.T) {
	stray := strayState(t)
	named := filepath.Join(t.TempDir(), "canary-named.state")
	for _, tc := range []struct {
		name          string
		r             runFlags
		state, url    string
		retains, says string
	}{
		{"nothing named: the hosted canary, never the stray file", runFlags{}, "", hostedCanaryURL, "30 minutes", "run by Summation"},
		{"-canary-url with its pin", runFlags{canaryURL: "https://control.sandprobe.test", canaryPin: testPin}, "", "https://control.sandprobe.test", "30 minutes", "the public canary you named"},
		{"-canary, named", runFlags{canary: named}, named, "", "", "which you run"},
		{"-canary over -canary-url", runFlags{canary: named, canaryURL: "https://control.sandprobe.test", canaryPin: testPin}, named, "", "", "which you run"},
		{"the stray file, only when named", runFlags{canary: stray}, stray, "", "", "the operator canary in " + stray},
	} {
		c, err := tc.r.chooseCanary()
		if err != nil || c.none || c.state != tc.state || c.url != tc.url || !strings.Contains(c.retainNote, tc.retains) || !strings.Contains(c.describe, tc.says) {
			t.Errorf("%s: %+v %v", tc.name, c, err)
		}
		if tc.r.canary == "" && strings.Contains(c.describe, stray) {
			t.Errorf("%s: the stray state file was chosen", tc.name)
		}
	}
	// SANDPROBE_CANARY names one as explicitly as the flag does.
	t.Setenv("SANDPROBE_CANARY", named)
	var r runFlags
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	r.register(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if c, err := r.chooseCanary(); err != nil || c.state != named {
		t.Errorf("SANDPROBE_CANARY: %+v %v", c, err)
	}
	if _, err := (runFlags{canaryPin: testPin}).chooseCanary(); err == nil {
		t.Error("a pin without its URL was set aside")
	}
}

// HCN-5: with one stray canary-*.state file and nothing named, every plan names the hosted canary, who runs it and
// HCN-4's retention, and never the stray file or its address: run exec and each native adapter, and providers too.
func TestStrayCanaryStateIsIgnored(t *testing.T) {
	stray := strayState(t)
	check := func(name, text string) {
		t.Helper()
		for _, want := range []string{"hosted canary at " + hostedCanaryURL, "run by Summation", "at most 30 minutes"} {
			if !strings.Contains(text, want) {
				t.Errorf("%s doesn't say %q", name, want)
			}
		}
		for _, bad := range []string{strayIP, stray, "stray.example", "SSM"} {
			if strings.Contains(text, bad) {
				t.Errorf("%s names %q", name, bad)
			}
		}
	}
	for _, args := range [][]string{
		{"plan", "exec", "-o", "json", "--", "sh"},
		{"plan", "baseten", "-o", "json"}, {"plan", "e2b", "-o", "json"}, {"plan", "vercel", "-o", "json"},
		{"plan", "cloudflare", "-o", "json"}, {"plan", "boat", "-o", "json"}, {"plan", "daytona", "-o", "json"},
		{"plan", "exe.dev", "-o", "json"},
	} {
		var out, errs bytes.Buffer
		if code := run(args, &out, &errs); code != 0 {
			t.Fatalf("%q: exit %d, %s", args, code, out.String()+errs.String())
		}
		var p planDoc
		if err := json.Unmarshal(out.Bytes(), &p); err != nil {
			t.Fatalf("%q: %v", args, err)
		}
		check(args[1], strings.Join(p.Contacts, " ")+" "+p.Residual)
	}
	// Sprites and AWS Nitro need a provider login before their plan, so their plans are built from the chooser.
	var r runFlags
	choice, err := r.chooseCanary()
	if err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]planDoc{
		"sprites":   sprPlan("example-org", choice, r, ""),
		"aws-nitro": nitroPlan("/k", choice, runFlags{variant: "isolated"}, host.PodSpec{Image: "i", RuntimeClass: "isolated-sandbox"}),
	} {
		check(name, strings.Join(p.Contacts, " ")+" "+p.Residual)
	}
	at, ok, fix := r.canaryReadiness()
	if !ok || fix != "" || !strings.Contains(at, hostedCanaryURL) || strings.Contains(at, strayIP) {
		t.Errorf("providers' canary: %q %v %q", at, ok, fix)
	}
	// Named, the same file is the operator canary, in the plan and in providers.
	var out, errs bytes.Buffer
	if code := run([]string{"plan", "e2b", "-canary", stray}, &out, &errs); code != 0 || !strings.Contains(out.String(), "the operator canary in "+stray) ||
		strings.Contains(out.String(), "hosted canary") {
		t.Errorf("-canary %s: exit %d, %s", stray, code, out.String()+errs.String())
	}
	if at, ok, _ := (runFlags{canary: stray}).canaryReadiness(); !ok || !strings.Contains(at, strayIP) {
		t.Errorf("providers with -canary: %q %v", at, ok)
	}
	if _, ok, fix := (runFlags{canary: filepath.Join(t.TempDir(), "missing.state")}).canaryReadiness(); ok || fix == "" {
		t.Error("providers called a missing operator canary ready")
	}
}

// standInHosted runs a real canary with the public control path on a local port and makes it the hosted canary for
// this test only: its URL, its pin, and a control client that trusts its certificate and dials it. No test reaches
// the real hosted canary.
func standInHosted(t *testing.T) *canary.Canary {
	t.Helper()
	const name = "control.sandprobe.test"
	c, err := canary.New("sandprobe.test")
	if err != nil {
		t.Fatal(err)
	}
	c.PublicAddr = "127.0.0.1"
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	leaf, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	controlKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pin, _ := canarycontrol.PinOf(&controlKey.PublicKey)
	stop := canarycontrol.Attach(c, name, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}},
		NextProtos: []string{"http/1.1"}}, controlKey)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go c.ServeTLS(ln, 443)
	addr := ln.Addr().String()
	client := &http.Client{Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: name},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			}}}
	url, pins, open := hostedCanaryURL, hostedCanaryPins, newPublicCanary
	hostedCanaryURL, hostedCanaryPins = "https://"+name, []string{pin}
	newPublicCanary = func(ctx context.Context, control string, pins []string) (*host.HTTPSCanary, error) {
		return host.NewHTTPSCanaryWithClient(ctx, control, pins, client)
	}
	t.Cleanup(func() {
		hostedCanaryURL, hostedCanaryPins, newPublicCanary = url, pins, open
		ln.Close()
		stop()
	})
	return c
}

// steadyHealth is a public canary whose health connects are taken as confirmed, so the test never dials ports on this
// machine; every control answer is still the real, signed one.
type steadyHealth struct{ *host.HTTPSCanary }

func (steadyHealth) Health(context.Context, int, canary.Key) bool { return true }

// surveyOnly answers the survey; its main run fails, which still leaves the canary's evidence gathered.
type surveyOnly struct{}

func (surveyOnly) ID() string { return "box-1" }
func (surveyOnly) Probe(_ context.Context, args []string, _ []byte) ([]byte, error) {
	if slices.Equal(args, []string{"-survey"}) {
		return json.Marshal(obs.Survey{Schema: obs.SurveySchema})
	}
	return nil, errors.New("no probe here")
}

// slotsFree: the canary holds nothing for this host, which can still reserve every slot one source may hold at once.
func slotsFree(t *testing.T, c *canary.Canary) {
	t.Helper()
	for i := 0; i < 4; i++ {
		q := canary.Request{Op: "reserve", TTL: 60, SecretSHA256: fmt.Sprintf("%064x", i+1), Challenge: strings.Repeat("ab", 32)}
		if a := c.HandlePublic(q, "127.0.0.1"); !a.OK {
			t.Fatalf("slot %d is held: %s", i, a.Error)
		}
	}
}

// HCN-5 for a native adapter, at the seam every one of them shares: with a stray operator state file and nothing
// named, the run's canary is the hosted one, proven by its signed status and holding the run's slot before any box
// exists (HCN-1, HCN-3); Execute arms, queries and disarms through it with the receipts read (SBX-11); and closeCanary
// gives everything back. A named operator canary that can't be loaded stops the run before anything.
func TestNativeRunOnTheHostedCanary(t *testing.T) {
	strayState(t)
	pub := standInHosted(t)
	var r runFlags
	choice, err := r.chooseCanary()
	if err != nil || choice.url != hostedCanaryURL {
		t.Fatalf("chose %+v %v", choice, err)
	}
	ctx := context.Background()
	var steps []string
	c, public, err := r.openCanary(ctx, choice, func(f string, a ...any) { steps = append(steps, fmt.Sprintf(f, a...)) })
	if err != nil || public == nil || c != host.Canary(public) || public.IP() != "127.0.0.1" || public.Domain() != "sandprobe.test" {
		t.Fatalf("open: %v %+v", err, public)
	}
	if len(steps) != 1 || !strings.Contains(steps[0], "signed status") {
		t.Errorf("steps %q", steps)
	}
	run, err := host.Execute(ctx, surveyOnly{}, steadyHealth{public}, host.Options{Mode: "exec", Excluded: host.E2BExclusions()})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	// Overloaded follows the kernel's drop counters, which only Linux exposes, so it isn't asserted here.
	if ev := run.Evidence; !ev.Live || !ev.ReceiptsRead {
		t.Fatalf("live %v, read %v", ev.Live, ev.ReceiptsRead)
	}
	var errs bytes.Buffer
	closeCanary(public, &errs)
	if errs.Len() != 0 {
		t.Fatalf("close: %s", errs.String())
	}
	slotsFree(t, pub)

	// The stray file, named but broken, is refused before any box: never a silent fallback to another canary.
	broken := filepath.Join(t.TempDir(), "canary-broken.state")
	os.WriteFile(broken, []byte("profile=p\n"), 0o600)
	r = runFlags{canary: broken}
	choice, _ = r.chooseCanary()
	if _, public, err := r.openCanary(ctx, choice, func(string, ...any) {}); err == nil || public != nil {
		t.Fatalf("a broken operator canary opened: %v", err)
	}
}

// HCN-7: canary check with nothing named, beside a stray operator state file, asks the canary a run would use: the
// hosted one under this release's pin, here a stand-in on a local port. It names that canary in text and JSON and
// reserves nothing. An operator canary, which answers only over SSM, and -tls-insecure without -canary-url are refused
// before any canary is asked, and a canary that doesn't sign under the pin is unproven.
func TestCanaryCheckDefaultsToTheHostedCanary(t *testing.T) {
	stray := strayState(t)
	pub := standInHosted(t)
	asked, open := 0, newPublicCanary
	newPublicCanary = func(ctx context.Context, control string, pins []string) (*host.HTTPSCanary, error) {
		asked++
		return open(ctx, control, pins)
	}
	t.Cleanup(func() { newPublicCanary = open })

	var out, errs bytes.Buffer
	if code := run([]string{"canary", "check"}, &out, &errs); code != 0 ||
		!strings.Contains(out.String(), "the hosted canary at "+hostedCanaryURL+", signed by the pinned control key") ||
		!strings.Contains(out.String(), "receipt address 127.0.0.1") || strings.Contains(out.String(), strayIP) {
		t.Fatalf("text: exit %d, %s%s", code, out.String(), errs.String())
	}
	out.Reset()
	var got map[string]string
	if code := run([]string{"canary", "check", "-o", "json"}, &out, &errs); code != 0 || json.Unmarshal(out.Bytes(), &got) != nil ||
		got["control"] != hostedCanaryURL || got["address"] != "127.0.0.1" || got["domain"] != "sandprobe.test" {
		t.Fatalf("json: exit %d, %s", code, out.String())
	}
	if asked != 2 {
		t.Fatalf("the hosted canary was asked %d times, not 2", asked)
	}
	slotsFree(t, pub)

	for _, tc := range []struct {
		args []string
		env  string
		says string
	}{
		{[]string{"canary", "check", "-canary", stray}, "", "answers only over SSM"},
		{[]string{"canary", "check"}, stray, "answers only over SSM"},
		{[]string{"canary", "check", "-tls-insecure"}, "", "-tls-insecure needs -canary-url"},
	} {
		t.Setenv("SANDPROBE_CANARY", tc.env)
		out.Reset()
		errs.Reset()
		if code := run(tc.args, &out, &errs); code != exitUsage || !strings.Contains(errs.String(), tc.says) || asked != 2 {
			t.Errorf("%q (SANDPROBE_CANARY %q): exit %d, asked %d, %s", tc.args, tc.env, code, asked, errs.String())
		}
	}
	t.Setenv("SANDPROBE_CANARY", "")

	// Under a pin the stand-in doesn't sign with, nothing it says is believed.
	hostedCanaryPins = []string{testPin}
	errs.Reset()
	if code := run([]string{"canary", "check"}, &out, &errs); code != exitLogin || !strings.Contains(errs.String(), "isn't proven") ||
		!strings.Contains(errs.String(), "reaches "+hostedCanaryURL) {
		t.Errorf("an unpinned key: exit %d, %s", code, errs.String())
	}
}

// HCN-5: the command line beats the environment. A stale SANDPROBE_CANARY never outranks an explicit -canary-url and
// -canary-pin; once any canary flag is given, every SANDPROBE_CANARY* value is set aside; with none, they stand in.
func TestCanaryFlagsBeatTheEnvironment(t *testing.T) {
	stale := strayState(t)
	plan := func(args ...string) (int, planDoc, string) {
		t.Helper()
		var out, errs bytes.Buffer
		code := run(append([]string{"plan"}, args...), &out, &errs)
		var p planDoc
		json.Unmarshal(out.Bytes(), &p)
		return code, p, out.String() + errs.String()
	}
	t.Setenv("SANDPROBE_CANARY", stale)
	code, p, text := plan("e2b", "-o", "json", "-canary-url", "https://control.sandprobe.test", "-canary-pin", testPin)
	if code != 0 || !strings.Contains(strings.Join(p.Contacts, " "), "the public canary you named at https://control.sandprobe.test") || strings.Contains(text, stale) {
		t.Errorf("a stale SANDPROBE_CANARY beside an explicit URL and pin: exit %d, %s", code, text)
	}
	// With no canary flag, the environment stands in for them.
	if code, p, text = plan("e2b", "-o", "json"); code != 0 || !strings.Contains(strings.Join(p.Contacts, " "), "the operator canary in "+stale) {
		t.Errorf("SANDPROBE_CANARY alone: exit %d, %s", code, text)
	}
	// A flag sets aside every environment value, the ones it doesn't name too.
	t.Setenv("SANDPROBE_CANARY", "")
	t.Setenv("SANDPROBE_CANARY_URL", "https://control.stale.test")
	t.Setenv("SANDPROBE_CANARY_PIN", testPin)
	if code, p, text = plan("e2b", "-o", "json", "-canary", stale); code != 0 || !strings.Contains(strings.Join(p.Contacts, " "), "the operator canary in "+stale) ||
		strings.Contains(text, "stale.test") {
		t.Errorf("-canary beside an environment URL: exit %d, %s", code, text)
	}
	if code, _, text = plan("e2b", "-o", "json", "-canary-url", "https://control.sandprobe.test"); code != exitUsage || !strings.Contains(text, "needs -canary-pin") {
		t.Errorf("an explicit URL took the environment's pin: exit %d, %s", code, text)
	}
	if code, _, text = plan("exec", "-o", "json", "-no-canary", "--", "sh"); code != 0 || !strings.Contains(text, "you chose -no-canary") {
		t.Errorf("-no-canary was refused for the environment's canary: exit %d, %s", code, text)
	}
}

// HCN-5, PRV-14: run docker always uses its local canary, so a canary flag is refused before anything runs (no Docker
// is on PATH here: a refusal that came any later would be Docker's error, not this one), and the environment's canary
// values are never read.
func TestDockerRefusesCanaryFlags(t *testing.T) {
	isolateCanary(t)
	t.Setenv("PATH", t.TempDir())
	for _, flags := range [][]string{
		{"-canary", "/nowhere.state"},
		{"-canary-url", "https://control.sandprobe.test", "-canary-pin", testPin},
		{"-canary-pin", testPin},
	} {
		for _, cmd := range []string{"plan", "run"} {
			var out, errs bytes.Buffer
			args := append(append([]string{cmd, "docker"}, flags...), "-y", "img")
			if code := run(args, &out, &errs); code != exitUsage || !strings.Contains(errs.String(), "its own local canary") {
				t.Errorf("%q: exit %d, %s %s", args, code, out.String(), errs.String())
			}
		}
	}
	t.Setenv("SANDPROBE_CANARY", "/nowhere.state")
	var out, errs bytes.Buffer
	if code := run([]string{"plan", "docker", "img"}, &out, &errs); code == exitUsage || strings.Contains(errs.String(), "local canary") {
		t.Errorf("the environment's canary reached run docker: exit %d, %s", code, errs.String())
	}
}

// stuckCleanup is a scratch removal that uses all of its budget and fails.
type stuckCleanup struct{}

func (stuckCleanup) Cleanup(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

// HCN-3, HCN-5: run exec gives back the hosted canary's slot under closeCanary's own budget, even after a scratch
// cleanup that used all of its own, so a slot is never held until it lapses.
func TestExecReleasesTheSlotAfterACancelledCleanup(t *testing.T) {
	isolateCanary(t)
	pub := standInHosted(t)
	limit := execCleanupLimit
	execCleanupLimit = 50 * time.Millisecond
	t.Cleanup(func() { execCleanupLimit = limit })
	var r runFlags
	choice, err := r.chooseCanary()
	if err != nil {
		t.Fatal(err)
	}
	_, public, err := r.openCanary(context.Background(), choice, func(string, ...any) {})
	if err != nil || public == nil {
		t.Fatalf("open: %v", err)
	}
	var errs bytes.Buffer
	cleanup, cleaned := execTeardown(stuckCleanup{}, "/tmp/sandprobe-x", public, &errs)
	if cleaned || !strings.Contains(cleanup, "NOT confirmed removed") {
		t.Fatalf("the stuck cleanup was called clean: %q", cleanup)
	}
	if strings.Contains(errs.String(), "slots weren't confirmed released") {
		t.Fatalf("the slot wasn't released: %s", errs.String())
	}
	slotsFree(t, pub)
}

// HCN-4, HCN-5: every plan that names a public canary (the hosted one, or one -canary-url names) states both
// addresses the canary keeps and for how long, from one shared sentence: run exec, a recipe, and each native adapter.
// A plan on an operator canary, and run docker's, say nothing of it.
func TestPublicCanaryPlansDiscloseRetention(t *testing.T) {
	stray := strayState(t)
	rc, err := shippedRecipe("kubernetes")
	if err != nil {
		t.Fatal(err)
	}
	box, err := host.NewRecipeBox(rc, "kind-test/default", "")
	if err != nil {
		t.Fatal(err)
	}
	// plans is every plan for one canary choice, named by its flags; each residual comes with what it would be with no
	// public canary at all.
	plans := func(flags []string) map[string][2]string {
		t.Helper()
		out := map[string][2]string{}
		r := runFlags{}
		fs := flag.NewFlagSet("plan", flag.ContinueOnError)
		r.register(fs)
		if err := fs.Parse(flags); err != nil {
			t.Fatal(err)
		}
		choice, err := r.chooseCanary()
		if err != nil {
			t.Fatal(err)
		}
		spec := host.PodSpec{Image: "i", RuntimeClass: "isolated-sandbox"}
		out["sprites"] = [2]string{sprPlan("org", choice, r, "").Residual, residual}
		out["aws-nitro"] = [2]string{nitroPlan("/k", choice, runFlags{variant: "isolated"}, spec).Residual, nitroResidual}
		out["kubernetes"] = [2]string{recipePlan(box, "", choice, nil, false).Residual, host.RecipeResidual(rc, box.Target, nil)}
		for name, base := range map[string]string{"exec": host.ExecResidual, "baseten": host.BasetenResidual, "e2b": host.E2BResidual,
			"vercel": host.VercelResidual, "cloudflare": host.CloudflareResidual, "boat": host.BoatResidual,
			"daytona": host.DaytonaResidual, "exe.dev": host.ExedevResidual} {
			args := append([]string{"plan", name, "-o", "json"}, flags...)
			if name == "exec" {
				args = append(args, "--", "sh")
			}
			var o, e bytes.Buffer
			if code := run(args, &o, &e); code != 0 {
				t.Fatalf("%q: exit %d, %s", args, code, o.String()+e.String())
			}
			var p planDoc
			if err := json.Unmarshal(o.Bytes(), &p); err != nil {
				t.Fatal(err)
			}
			out[name] = [2]string{p.Residual, base}
		}
		return out
	}
	for _, flags := range [][]string{nil, {"-canary-url", "https://control.sandprobe.test", "-canary-pin", testPin}} {
		got := plans(flags)
		if len(got) != 11 {
			t.Fatalf("%d plans", len(got))
		}
		for name, res := range got {
			if res[0] != res[1]+" "+publicCanaryRetention {
				t.Errorf("%v %s: the residual isn't its own plus the shared retention: %q", flags, name, res[0])
			}
		}
	}
	for _, want := range []string{"the box's public address", "with this run's random nonces", "at most 30 minutes",
		"the public address of the machine running Sandprobe", "in a rate counter for at most an hour", "in memory only", "stores nothing"} {
		if !strings.Contains(publicCanaryRetention, want) {
			t.Errorf("the shared retention doesn't say %q", want)
		}
	}
	// An operator canary, and run docker's local one, are unchanged: no public canary's retention.
	for name, res := range plans([]string{"-canary", stray}) {
		if res[0] != res[1] {
			t.Errorf("operator canary, %s: %q", name, res[0])
		}
	}
	if d := dockerPlan("img", "root", nil); d.Residual != dockerResidual || strings.Contains(strings.Join(d.Contacts, " "), "rate counter") {
		t.Errorf("the docker plan changed: %+v", d)
	}
}
