package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"sandprobe/internal/catalog"
	"sandprobe/internal/grade"
	"sandprobe/internal/obs"
)

// notBuilt are the checks the probe doesn't implement yet. Until they exist they end unknown, so no fixture can
// reach A or B (GRD-2), and each fixture says so rather than skipping them.
var notBuilt = []string{}

const probeInBox = "/opt/sandprobe/sandprobe-probe"

// world is what the fixtures run beside: the network, the canary, and the stub (metadata at 169.254.169.254 on its
// own link-local network, and a stand-in Kubernetes API on the fixture network).
type world struct {
	network, canaryIP, meta, stub, stubIP, canary string
}

type fixture struct {
	name    string                 // the test's name
	image   string                 // test/fixtures/<image>; the name when empty
	user    string                 // the agent's user; "agent" when empty
	opts    func(w world) []string // docker run options
	meta    bool                   // also attached to the metadata network
	volumes []string               // where the persistent volumes Sandprobe creates for the run are mounted
	box     func(d *DockerBox) Box // wraps the box: a reset hook, or another reset model
	hold    bool                   // a container holds the first volume at teardown, so it can't be deleted
	tdErr   string                 // teardown must fail, saying this: something Sandprobe made isn't confirmed gone
	local   bool                   // the person approved contacting a local proxy (-allow-local-proxy)
	probe   string                 // "arch": built for an architecture the box can't run; "copy": copied onto noexec storage; "fault": the fault-injection build; "liar": a substitute
	pause   bool                   // the canary paused for the run: down while egress is open
	settle  time.Duration          // time the box's entrypoint needs to set its case up before the run
	wantErr string                 // the run must stop before any grade, saying this (invalid, no letter: exit 5)
	expect  func(t *testing.T, w world, r *Run)
}

var lockedDown = []string{"--network", "none", "--read-only", "--tmpfs", "/tmp", "--cap-drop", "ALL", "--security-opt", "no-new-privileges"}

var fixtures = []fixture{
	{name: "clean", opts: func(world) []string { return lockedDown }, expect: expectClean},
	{name: "holes", meta: true, volumes: []string{"/home/agent/persist"}, expect: expectHoles, opts: func(w world) []string {
		return []string{"--network", w.network, "--dns", w.canaryIP,
			"-e", "KUBERNETES_SERVICE_HOST=" + w.stubIP, "-e", "KUBERNETES_SERVICE_PORT=443"}
	}},
	// broken: the probe can't run at all, so nothing is graded
	{name: "broken-arch", image: "clean", probe: "arch", wantErr: "exec format error", opts: func(world) []string { return lockedDown }},
	{name: "broken-noexec", image: "clean", probe: "copy", wantErr: "permission denied", opts: func(world) []string {
		return []string{"--network", "none", "--tmpfs", "/opt/sandprobe:noexec,mode=0755"}
	}},
	// network: no refusal without TWN-1's full proof ever passes, and each port stands on its own
	{name: "net-one-port", image: "net", expect: expectNetOnePort, opts: func(w world) []string {
		return []string{"--network", w.network, "--dns", w.canaryIP, "--cap-add", "NET_ADMIN", "-e", "ONE_PORT_CANARY=" + w.canaryIP}
	}},
	// exported: real runs of local boxes, saved as bundles for the public test reports in test/reports (see its README)
	{name: "export-egress-open", image: "net", user: "root", expect: exportOpen, opts: func(w world) []string {
		return []string{"--network", w.network, "--dns", w.canaryIP, "--cap-add", "NET_ADMIN", "--security-opt", "no-new-privileges"} // the refused box's identity, no firewall
	}},
	{name: "export-egress-refused", image: "net", user: "root", settle: time.Second, expect: exportRefused, opts: func(w world) []string {
		return []string{"--network", w.network, "--dns", w.canaryIP, "--cap-add", "NET_ADMIN", "--security-opt", "no-new-privileges", "-e", "REFUSE_CANARY=" + w.canaryIP}
	}},
	{name: "export-canary-down", image: "net", user: "root", pause: true, expect: exportCanaryDown, opts: func(w world) []string {
		return []string{"--network", w.network, "--dns", w.canaryIP}
	}},
	{name: "net-local-resolver", image: "clean", expect: expectLocalResolver, opts: func(w world) []string {
		return []string{"--network", w.network, "--dns", w.stubIP}
	}},
	{name: "net-canary-down", image: "clean", pause: true, expect: expectCanaryUnknown, opts: func(w world) []string {
		return []string{"--network", w.network, "--dns", w.canaryIP}
	}},
	faultCase("skip-refused", "an immediate refused never counts"), faultCase("skip-inprogress", "no SYN_SENT seen"),
	faultCase("prebind-refused", "an immediate refused never counts"),
	faultCase("hostunreach", "without the kernel's route lookup agreeing"), faultCase("eperm", "an immediate eperm never counts"),
	// evidence: each finding with the evidence class it earns, and scoping that is never an absence
	{name: "evidence-peer", image: "evidence", settle: time.Second, expect: expectPeer, opts: func(world) []string {
		return []string{"--network", "none", "-e", "EVIDENCE=peer"}
	}},
	{name: "evidence-hidepid", image: "evidence", settle: time.Second,
		expect: expectResults(map[string]string{"SEC-2": obs.ScopedOut, "SEC-5": obs.ScopedOut}), opts: func(world) []string {
			return []string{"--network", "none", "--cap-add", "SYS_ADMIN", "-e", "EVIDENCE=hidepid"}
		}},
	{name: "evidence-sockets", image: "evidence", settle: time.Second, expect: expectSockets, opts: func(world) []string {
		return []string{"--network", "none", "--cap-add", "NET_ADMIN", "-e", "EVIDENCE=sockets"}
	}},
	// deceptive: a box trying to fool the probe; no affected check passes, and nothing it plants is run or opened
	deceptive("sudo-shims", expectSudoShims, "--network", "none",
		"-e", "PATH=/home/agent/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
	deceptive("sudo-4777", expectAMP1Deceived(obs.Unknown, ""), "--network", "none"),
	deceptive("sudo-prompt", expectAMP1Deceived(obs.Finding, "nopasswd_all"), "--network", "none"),
	deceptive("curl", expectCurlUntouched, "--network", "none"),
	{name: "deceptive-preload", image: "deceptive", settle: time.Second, expect: expectPreload, opts: func(w world) []string {
		return []string{"--network", w.network, "--dns", w.canaryIP, "-e", "DECEPTIVE=preload", "-e", "LD_PRELOAD=/usr/lib/failconnect.so"}
	}},
	{name: "deceptive-proxy403", image: "deceptive", settle: time.Second, expect: expectProxy403, opts: func(w world) []string {
		return []string{"--network", w.network, "--dns", w.canaryIP, "-e", "HTTPS_PROXY=http://" + w.stubIP + ":3128"}
	}},
	{name: "deceptive-proxy-creds", image: "deceptive", settle: time.Second, expect: expectProxyCreds, opts: func(w world) []string {
		return []string{"--network", w.network, "--dns", w.canaryIP, "-e", "HTTPS_PROXY=http://sandprobe-user:sandprobe-fake@" + w.stubIP + ":3128"}
	}},
	{name: "deceptive-intercept", image: "deceptive", settle: time.Second, expect: expectIntercepted, opts: func(w world) []string {
		return []string{"--network", w.network, "--dns", w.canaryIP, "--cap-add", "NET_ADMIN", "-e", "DECEPTIVE=intercept",
			"-e", "CANARY_IP=" + w.canaryIP, "-e", "STUB_IP=" + w.stubIP}
	}},
	// reset: PER-5 against resets that go wrong. A marker survives only to a proven reset, and only a whole recheck
	// after a proven reset is not_found.
	{name: "reset-volume-swapped", image: "reset", volumes: []string{"/home/agent/persist"}, tdErr: "volume",
		box: hooked(func(ctx context.Context, stage string, d *DockerBox) {
			if stage == "removed" { // a volume made again under the same name, while the box is away
				dockerQuiet(ctx, "volume", "rm", d.Vols[0])
				dockerQuiet(ctx, "volume", "create", d.Vols[0])
			}
		}), expect: expectPER5(obs.Unknown, "isn't the same storage"), opts: noNet},
	{name: "reset-remounted", image: "reset", volumes: []string{"/home/agent/persist"},
		box: hooked(func(ctx context.Context, stage string, d *DockerBox) {
			if stage == "removed" { // the same volume, mounted elsewhere in the new box
				for i, a := range d.Args {
					d.Args[i] = strings.Replace(a, ":/home/agent/persist", ":/home/agent/persist2", 1)
				}
			}
		}), expect: expectPER5(obs.Unknown, "isn't the same storage"), opts: noNet},
	{name: "reset-cleaner", image: "reset", volumes: []string{"/home/agent/persist"}, box: hooked(cleaner("/home/agent/persist")),
		expect: expectPER5(obs.NotFound, "something other than the reset may have removed it"), opts: noNet},
	{name: "reset-refusing-root", image: "reset", volumes: []string{"/home/agent/persist", "/home/agent/locked"},
		box: hooked(cleaner("/home/agent/persist")), opts: noNet,
		expect: expectPER5(obs.Unknown, "/home/agent/locked took no marker: the agent can't write it (EACCES), so the survey didn't list it")},
	{name: "reset-substitute", image: "reset", volumes: []string{"/home/agent/persist"}, box: hooked(substitute("/home/agent/persist")),
		expect: expectSubstitute, opts: noNet},
	{name: "reset-held-volume", image: "reset", volumes: []string{"/home/agent/persist"}, hold: true, tdErr: "volume",
		expect: expectPER5(obs.Finding, "survived"), opts: noNet},
	{name: "reset-restart", image: "reset", box: restarted(false, "/home/agent"), expect: expectRestart, opts: noNet},
	{name: "reset-restore-fails", image: "reset", box: restarted(true), expect: expectPER5(obs.Unknown, "operation done"), opts: noNet},
	// effects: nothing changed but what's allowed, nothing opened that mustn't be, no local service touched unapproved
	{name: "effects-watch", image: "effects", settle: 1500 * time.Millisecond, expect: expectUntouched, opts: func(world) []string {
		return []string{"--network", "none", "-e", "EFFECTS=watch"}
	}},
	{name: "effects-dangling", image: "effects", settle: time.Second, expect: expectSEC3Dangling, opts: func(world) []string {
		return []string{"--network", "none", "-e", "EFFECTS=dangling"}
	}},
	{name: "effects-proxy-unapproved", image: "effects", settle: time.Second, expect: expectLocalProxy(false), opts: localProxy},
	{name: "effects-proxy-approved", image: "effects", settle: time.Second, local: true, expect: expectLocalProxy(true), opts: localProxy},
	// substitute: the probe swapped inside the box for a liar with the expected digest. SBX-10 says this isn't detected,
	// and the fixture records exactly that: an open box, every proof fabricated, graded A.
	{name: "substitute", image: "holes", probe: "liar", expect: expectSubstituted, opts: func(w world) []string {
		return []string{"--network", w.network, "--dns", w.canaryIP}
	}},
	// policy: sudo listings AMP-1 must never pass, and must never act on
	{name: "policy-listpw", image: "policy", user: "listpw", opts: func(world) []string { return []string{"--network", "none"} },
		expect: expectAMP1(obs.NotFound, "")},
	{name: "policy-passwd", image: "policy", user: "passwd", opts: func(world) []string { return []string{"--network", "none"} },
		expect: expectAMP1(obs.NotFound, "")},
	{name: "policy-truepath", image: "policy", user: "truepath", opts: func(world) []string { return []string{"--network", "none"} },
		expect: expectAMP1(obs.Finding, "nopasswd_named")},
	// sudors: sudo-rs as Ubuntu ships it, a chain of links to the setuid file, followed and run through the pinned file;
	// a chain the agent could redirect, or that ends nowhere, never runs, and AMP-1 says why
	sudors("nopasswd", "agent", obs.Finding, "nopasswd_all", "run from "+sudoChain),
	sudors("norule", "plain", obs.NotFound, "", "run from "+sudoChain),
	// a hardened agent: no capabilities and NoNewPrivs, under which the kernel ignores setuid and sudo-rs stops at once
	sudors("hardened", "plain", obs.NotFound, "", "run from "+sudoChain, "--cap-drop", "ALL", "--security-opt", "no-new-privileges"),
	sudors("root", "root", obs.Unknown, "", "the agent can write /usr/bin, so it could replace /usr/bin/sudo"),
	sudors("writable-link", "agent", obs.Unknown, "", "the agent can write /etc/alternatives, so it could replace /etc/alternatives/sudo"),
	sudors("writable-real", "agent", obs.Unknown, "", "the agent can write /opt/alt, so it could replace /opt/alt/alternatives/sudo"),
	sudors("dangling", "agent", obs.Unknown, "", "its links can't be followed to a file"),
}

const sudoChain = "/usr/bin/sudo -> /etc/alternatives/sudo -> /usr/lib/cargo/bin/sudo"

// sudors is a case of the sudors fixture: SUDORS sets it up, and AMP-1 must end as result and variant, saying says.
// The agent user has NOPASSWD for every command, so a refused case that ran sudo would show as a finding.
func sudors(mode, user, result, variant, says string, opts ...string) fixture {
	return fixture{name: "sudors-" + mode, image: "sudors", user: user, settle: time.Second,
		opts: func(world) []string { return append([]string{"--network", "none", "-e", "SUDORS=" + mode}, opts...) },
		expect: func(t *testing.T, w world, r *Run) {
			if o := outcome(r.Report, "AMP-1"); o.Result != result || o.Variant != variant || !strings.Contains(o.Evidence+o.Reason, says) {
				t.Errorf("AMP-1: want %s %s saying %q, got %+v", result, variant, says, o)
			}
		}}
}

// TestFixtures runs each fixture box beside a local canary, through the whole host path, and checks it gives its
// expected result (Tests). It needs Docker: test/fixtures.sh builds the images and runs it.
func TestFixtures(t *testing.T) {
	if os.Getenv("SANDPROBE_FIXTURES") == "" {
		t.Skip("needs Docker: run test/fixtures.sh")
	}
	ctx := context.Background()
	work := t.TempDir()
	arch := strings.TrimSpace(run(t, "docker", "info", "--format", "{{.Architecture}}"))
	arch = map[string]string{"x86_64": "amd64", "aarch64": "arm64"}[arch]
	probe, canaryBin, stubBin := filepath.Join(work, "sandprobe-probe"), filepath.Join(work, "sandprobe-canary"), filepath.Join(work, "stub")
	faulty := filepath.Join(work, "sandprobe-probe-faults") // the fault-injection build: never shipped
	cmd := exec.Command("go", "build", "-tags", "sandprobe_faults", "-o", faulty, "sandprobe/cmd/sandprobe-probe")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+arch)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building the fault probe: %v\n%s", err, b)
	}
	fb, _ := os.ReadFile(faulty)
	fsum := sha256.Sum256(fb)
	faultDigest := hex.EncodeToString(fsum[:])
	foreign := filepath.Join(work, "sandprobe-probe-loong64") // an architecture Docker Desktop doesn't emulate
	cmd = exec.Command("go", "build", "-o", foreign, "sandprobe/cmd/sandprobe-probe")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=loong64")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building the foreign probe: %v\n%s", err, b)
	}
	for pkg, out := range map[string]string{"sandprobe/cmd/sandprobe-probe": probe, "sandprobe/cmd/sandprobe-canary": canaryBin,
		"sandprobe/test/fixtures/stub": stubBin} {
		cmd := exec.Command("go", "build", "-o", out, pkg)
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+arch)
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("building %s: %v\n%s", pkg, err, b)
		}
	}
	b, _ := os.ReadFile(probe)
	sum := sha256.Sum256(b)
	digest := hex.EncodeToString(sum[:])
	liar := filepath.Join(work, "liar") // a substitute that reports the shipped probe's digest and fabricates every proof
	cmd = exec.Command("go", "build", "-ldflags", "-X main.digest="+digest, "-o", liar, "sandprobe/test/fixtures/liar")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+arch)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building the liar: %v\n%s", err, b)
	}

	w := world{network: fmt.Sprintf("sp-fx-%d", os.Getpid()), canaryIP: "172.30.98.10", meta: fmt.Sprintf("sp-meta-%d", os.Getpid()),
		stubIP: "172.30.98.20"}
	run(t, "docker", "network", "create", "--subnet", "172.30.98.0/24", w.network)
	t.Cleanup(func() { exec.Command("docker", "network", "rm", w.network).Run() })
	run(t, "docker", "network", "create", "--subnet", "169.254.169.0/24", w.meta)
	t.Cleanup(func() { exec.Command("docker", "network", "rm", w.meta).Run() })
	c, err := StartDockerCanary(ctx, w.network, w.canaryIP, "debian:trixie-slim", canaryBin, "sandprobe.test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Stop)
	w.canary = c.Container
	w.stub = strings.TrimSpace(run(t, "docker", "run", "-d", "--network", w.network, "--ip", w.stubIP, "-v", stubBin+":/stub:ro",
		"debian:trixie-slim", "/stub"))
	t.Cleanup(func() { exec.Command("docker", "rm", "-f", w.stub).Run() })
	run(t, "docker", "network", "connect", "--ip", "169.254.169.254", w.meta, w.stub)

	for _, fx := range fixtures {
		t.Run(fx.name, func(t *testing.T) {
			args := append([]string{"run", "-d"}, fx.opts(w)...)
			var vols []string
			for i, mp := range fx.volumes {
				vol := fmt.Sprintf("sp-fx-%d-%s-%d", os.Getpid(), fx.name, i)
				run(t, "docker", "volume", "create", vol)
				t.Cleanup(func() { exec.Command("docker", "volume", "rm", "-f", vol).Run() })
				args, vols = append(args, "-v", vol+":"+mp), append(vols, vol)
			}
			image, user := fx.image, fx.user
			if image == "" {
				image = fx.name
			}
			if user == "" {
				user = "agent"
			}
			switch fx.probe {
			case "arch":
				args = append(args, "-v", foreign+":"+probeInBox+":ro")
			case "fault":
				args = append(args, "-v", faulty+":"+probeInBox+":ro")
			case "liar": // the box swapped the host's probe for its own
				args = append(args, "-v", liar+":"+probeInBox+":ro")
			case "": // the host's copy, bind-mounted read-only
				args = append(args, "-v", probe+":"+probeInBox+":ro")
			}
			args = append(args, "sandprobe-fixture-"+image)
			id := strings.TrimSpace(run(t, "docker", args...))
			t.Cleanup(func() { exec.Command("docker", "rm", "-f", id).Run() })
			if fx.meta {
				run(t, "docker", "network", "connect", w.meta, id)
			}
			time.Sleep(fx.settle)
			if fx.probe == "copy" { // copied in through the provider, as a real adapter does, onto the box's storage
				cp := exec.Command("docker", "exec", "-i", "-u", "root", id, "sh", "-c", "cat > "+probeInBox+" && chmod 0755 "+probeInBox)
				f, _ := os.Open(probe)
				cp.Stdin = f
				if b, err := cp.CombinedOutput(); err != nil {
					t.Fatalf("copying the probe in: %v %s", err, b)
				}
				f.Close()
			}
			box := &DockerBox{Container: id, User: user, ProbePath: probeInBox, Args: args, Vols: vols}
			sum := digest
			if fx.probe == "fault" {
				sum = faultDigest
			}
			if fx.pause {
				run(t, "docker", "pause", w.canary)
				defer exec.Command("docker", "unpause", w.canary).Run()
			}
			var target Box = box
			if fx.box != nil {
				target = fx.box(box)
			}
			r, err := Execute(ctx, target, c, Options{Mode: "exec", ProbeSHA256: sum, AllowLocalProxy: fx.local})
			if fx.pause {
				exec.Command("docker", "unpause", w.canary).Run()
			}
			if fx.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), fx.wantErr) {
					t.Fatalf("want no grade, stopped by %q; got %v (report %+v)", fx.wantErr, err, r)
				}
				t.Logf("no grade, as it should be: %v", err)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { exec.Command("docker", "rm", "-f", r.Box.ID()).Run() })
			defer func() { // after the expectations, which look inside the box
				if fx.hold { // something else keeps the volume, so it can't be deleted
					holder := strings.TrimSpace(run(t, "docker", "run", "-d", "--rm", "-v", vols[0]+":/held", "debian:trixie-slim", "sleep", "60"))
					defer exec.Command("docker", "kill", holder).Run()
				}
				err := Teardown(ctx, r)
				if fx.tdErr != "" { // loud, naming what remains, and no marker on it reported gone (PRV-3, SBX-1)
					if err == nil || !strings.Contains(err.Error(), fx.tdErr) {
						t.Errorf("teardown: want an error naming %q, got %v", fx.tdErr, err)
					}
					for _, mk := range r.Markers {
						if mk.Gone {
							t.Errorf("marker %s reported gone with its volume left: %s", mk.Path, mk.How)
						}
					}
					return
				}
				if err != nil { // every marker gone only with a deletion Docker confirmed (SBX-1)
					t.Error(err)
				}
				for _, mk := range r.Markers {
					if !mk.Gone {
						t.Errorf("marker %s: %s", mk.Path, mk.How)
					}
				}
			}()
			logRun(t, r)
			if !r.Report.Valid {
				t.Fatalf("invalid run: %s", r.Report.Invalid)
			}
			if bytes.Contains(r.Doc, []byte("sandprobe-fake")) { // SBX-1, SBX-2: never a secret's value
				t.Fatal("a fake secret's value reached the probe's document")
			}
			fx.expect(t, w, r)
		})
	}
}

func expectClean(t *testing.T, w world, r *Run) {
	rep := r.Report
	for _, o := range rep.Outcomes {
		ck, _ := catalog.Get(o.ID)
		if o.Result == obs.Finding {
			t.Errorf("%s: a finding in the clean box: %s %s", o.ID, o.Variant, o.Evidence)
		}
		if ck.Kind == catalog.TwoSided && o.Result == obs.Unknown {
			t.Errorf("%s: a two-sided check must be exercised in the clean box, got unknown: %s", o.ID, o.Reason)
		}
		if o.Result == obs.Unknown && !slices.Contains(notBuilt, o.ID) {
			t.Errorf("%s: unknown: %s", o.ID, o.Reason)
		}
	}
	for _, id := range []string{"EGR-3", "EGR-6", "AMP-6", "PER-5"} {
		if rep.Skipped[id] == "" {
			t.Errorf("%s should be skipped and listed", id)
		}
	}
	for id, want := range map[string]string{"AMP-1": obs.Absent, "SEC-4": obs.NotFound, "AMP-7": obs.NotFound} {
		if o := outcome(rep, id); o.Result != want {
			t.Errorf("%s: want %s, got %+v", id, want, o)
		}
	}
	want := "A"
	if len(rep.Unknown) > 0 {
		want = "C" // GRD-2: never A or B while anything is unknown
	}
	if rep.Letter != want {
		t.Errorf("want %s, got %s", want, rep.Letter)
	}
}

func expectHoles(t *testing.T, w world, r *Run) {
	rep := r.Report
	if rep.Letter != "F" {
		t.Errorf("want F, got %s", rep.Letter)
	}
	found := map[string]grade.Outcome{}
	for _, o := range rep.Outcomes {
		if o.Result == obs.Finding {
			found[o.ID] = o
		}
	}
	for id, variants := range map[string][]string{
		"SEC-1": {"names"}, "SEC-3": {"nonempty", "k8s_token"}, "PER-1": {"writable"}, "AMP-4": {"control_socket"},
		"EGR-1": {"receipt"}, "EGR-2": {"receipt"}, "EGR-5.22": {"receipt"}, "EGR-5.80": {"receipt"},
		"EGR-5.8080": {"receipt"}, "EGR-5.53u": {"receipt"},
		"SEC-4": {"role_listed"}, "AMP-1": {"nopasswd_all"}, "AMP-7": {"k8s_api"}, "PER-5": {"survived", "survived_startup"},
	} {
		if o, ok := found[id]; !ok || !slices.Contains(variants, o.Variant) {
			t.Errorf("%s: want a finding (%v), got %+v", id, variants, o)
		}
	}
	var chn1 *grade.Finding
	for i, f := range rep.Findings {
		if f.ID == "CHN-1" {
			chn1 = &rep.Findings[i]
		}
	}
	if chn1 == nil || chn1.Potential || chn1.Severity != catalog.Critical {
		t.Errorf("want CHN-1 confirmed from the non-empty credential and a receipt, got %+v", chn1)
	}
	if o := outcome(rep, "SEC-4"); o.Class != catalog.Indicator { // a listed role shows exposure, not a credential in hand
		t.Errorf("SEC-4's role listing: want an indicator, got %+v", o)
	}
	if !slices.ContainsFunc(rep.Findings, func(f grade.Finding) bool { return f.ID == "CHN-3" }) {
		t.Error("want CHN-3: a service account token and a reachable Kubernetes API")
	}
	if !slices.ContainsFunc(rep.Notes, func(n string) bool { return strings.HasPrefix(n, "CHN-2") }) {
		t.Error("want CHN-2's note: sudo NOPASSWD for everything is root-equivalent")
	}
	// SBX-2 and SBX-3 at the stub: role names were listed, the role's credential document never asked for, and the
	// Kubernetes API got a handshake and no request.
	stubLog := run(t, "docker", "logs", w.stub)
	switch {
	case !strings.Contains(stubLog, "GET /latest/meta-data/iam/security-credentials/\n"):
		t.Errorf("the role listing was never asked for:\n%s", stubLog)
	case strings.Contains(stubLog, "security-credentials/sandprobe-fixture-role"):
		t.Errorf("the probe asked for a credential document:\n%s", stubLog)
	case !strings.Contains(stubLog, "tls handshake"), strings.Contains(stubLog, "tls request"):
		t.Errorf("want one TLS handshake with the stand-in API and no request:\n%s", stubLog)
	}
}

func outcome(r grade.Report, id string) grade.Outcome {
	for _, o := range r.Outcomes {
		if o.ID == id {
			return o
		}
	}
	return grade.Outcome{}
}

func logRun(t *testing.T, r *Run) {
	for _, o := range r.Report.Outcomes {
		t.Logf("%-10s %-10s %-16s %s%s", o.ID, o.Result, o.Variant, o.Evidence, o.Reason)
	}
	for id, why := range r.Report.Skipped {
		t.Logf("%-10s skipped    %s", id, why)
	}
	t.Logf("grade %s complete=%v unknown=%v; launched-to-returned %v, %d receipts", r.Report.Letter, r.Report.Complete,
		r.Report.Unknown, r.Evidence.Returned.Sub(r.Evidence.Launched).Round(1e6), len(r.Evidence.Receipts))
	if ev := r.Evidence.Reset; ev != nil {
		t.Logf("reset: %s %s, %s -> %s, done=%v", ev.Model, ev.OperationID, ev.BoxBefore, ev.BoxAfter, ev.Done)
	}
}

func run(t *testing.T, name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		msg := ""
		if ee, ok := err.(*exec.ExitError); ok {
			msg = string(ee.Stderr)
		}
		t.Fatalf("%s %v: %v %s", name, args, err, msg)
	}
	return string(out)
}

// Docker deletes volumes by name; teardown deletes one only while the name still names the volume Sandprobe created
// (name and creation time), and reports it gone only on Docker's definitive "no such volume".
func TestDockerTeardownIdentity(t *testing.T) {
	if os.Getenv("SANDPROBE_FIXTURES") == "" {
		t.Skip("needs Docker: run test/fixtures.sh")
	}
	ctx := context.Background()
	name := fmt.Sprintf("sp-fx-%d-ident", os.Getpid())
	t.Cleanup(func() { exec.Command("docker", "volume", "rm", "-f", name).Run() })
	run(t, "docker", "volume", "create", name)
	created := strings.TrimSpace(run(t, "docker", "volume", "inspect", "-f", "{{.CreatedAt}}", name))
	planned := obs.Volume{ID: name + "@" + created, MountPath: "/data"}
	// someone else's volume made under the same name after the plan
	run(t, "docker", "volume", "rm", name)
	time.Sleep(1100 * time.Millisecond) // CreatedAt has one-second resolution
	run(t, "docker", "volume", "create", name)
	d := &DockerBox{Container: "sp-fx-no-such-container"}
	gone := d.Teardown(ctx, []obs.Volume{planned})
	if gone[planned.ID] {
		t.Error("a volume made again under the name was reported as Sandprobe's, gone")
	}
	if exec.Command("docker", "volume", "inspect", name).Run() != nil {
		t.Error("teardown deleted a volume that isn't the one Sandprobe created")
	}
	if !gone[""] {
		t.Error("a container that doesn't exist: want Docker's definitive answer, gone")
	}
	// the planned volume itself, still in place: deleted and confirmed
	planned.ID = name + "@" + strings.TrimSpace(run(t, "docker", "volume", "inspect", "-f", "{{.CreatedAt}}", name))
	if gone := d.Teardown(ctx, []obs.Volume{planned}); !gone[planned.ID] {
		t.Error("Sandprobe's own volume: want it deleted and confirmed gone")
	}
}

// expectAMP1 checks AMP-1 ended as want, never a pass, and that no command ran through sudo: the policy fixture's
// sentinel, written by the box's own true if sudo ever ran it, isn't there.
func expectAMP1(result, variant string) func(t *testing.T, w world, r *Run) {
	return func(t *testing.T, w world, r *Run) {
		if o := outcome(r.Report, "AMP-1"); o.Result != result || o.Variant != variant {
			t.Errorf("AMP-1: want %s %s, got %+v", result, variant, o)
		}
		if sentinelPresent(t, r.Box.ID()) {
			t.Error("a command ran through sudo: the sentinel was written")
		}
	}
}

// sentinelPresent looks inside a running box for the policy fixture's sentinel. Not being able to look fails the
// test, so a box that's already gone can never read as "no sentinel".
func sentinelPresent(t *testing.T, box string) bool {
	t.Helper()
	out, err := exec.Command("docker", "exec", box, "sh", "-c",
		"if [ -e /tmp/sentinel-true-ran ]; then echo present; else echo absent; fi").Output()
	switch got := strings.TrimSpace(string(out)); {
	case err != nil:
		t.Fatalf("can't look for the sentinel in %s: %v", box, err)
	case got == "present":
		return true
	case got != "absent":
		t.Fatalf("looking for the sentinel: %q", got)
	}
	return false
}

// The sentinel check sees a sentinel that's there, and fails rather than pass on a box that's gone.
func TestSentinelCheck(t *testing.T) {
	if os.Getenv("SANDPROBE_FIXTURES") == "" {
		t.Skip("needs Docker: run test/fixtures.sh")
	}
	id := strings.TrimSpace(run(t, "docker", "run", "-d", "--network", "none", "sandprobe-fixture-policy"))
	defer exec.Command("docker", "rm", "-f", id).Run()
	if sentinelPresent(t, id) {
		t.Fatal("a fresh box has no sentinel")
	}
	run(t, "docker", "exec", id, "touch", "/tmp/sentinel-true-ran")
	if !sentinelPresent(t, id) {
		t.Fatal("a planted sentinel must be seen")
	}
	exec.Command("docker", "rm", "-f", id).Run()
	if out, err := exec.Command("docker", "exec", id, "true").CombinedOutput(); err == nil {
		t.Fatalf("the box should be gone: %s", out)
	}
}

// faultCase runs the fault-injection probe on an open network: SANDPROBE_FAULT makes connect report a refusal, or an
// unreachable host, or a permission error, without the kernel ever trying. No such refusal may pass (TWN-1).
func faultCase(fault, reason string) fixture {
	return fixture{name: "net-fault-" + fault, image: "clean", probe: "fault", expect: expectNoDirectPass(reason), opts: func(w world) []string {
		return []string{"--network", w.network, "--dns", w.canaryIP, "-e", "SANDPROBE_FAULT=" + fault}
	}}
}

var directTCP = []string{"EGR-2", "EGR-5.22", "EGR-5.80", "EGR-5.8080"}

func expectResults(want map[string]string) func(t *testing.T, w world, r *Run) {
	return func(t *testing.T, w world, r *Run) {
		for id, result := range want {
			if o := outcome(r.Report, id); o.Result != result {
				t.Errorf("%s: want %s, got %+v", id, result, o)
			}
		}
	}
}

// canaryWorked: the canary was live and its receipts read, so a result rests on the evidence, not on a broken canary.
func canaryWorked(t *testing.T, r *Run) {
	t.Helper()
	if !r.Evidence.Live || !r.Evidence.ReceiptsRead {
		t.Fatalf("the canary must be live with its receipts read for this case: live=%v read=%v", r.Evidence.Live, r.Evidence.ReceiptsRead)
	}
}

// Only tcp/443 leaves: EGR-2 is found by its receipt, every other TCP port passes on its own proof, and UDP to the
// canary, rejected, leaves no receipt.
func expectNetOnePort(t *testing.T, w world, r *Run) {
	canaryWorked(t, r)
	expectResults(map[string]string{"EGR-2": obs.Finding, "EGR-5.22": obs.Pass, "EGR-5.80": obs.Pass, "EGR-5.8080": obs.Pass,
		"EGR-5.53u": obs.NotFound})(t, w, r)
}

// A resolver that answers our name itself: it saw this run's EGR-1 query, the canary never did, and EGR-1 is
// not_found, never a pass.
func expectLocalResolver(t *testing.T, w world, r *Run) {
	canaryWorked(t, r)
	nonce := r.Manifest.CheckNonces["EGR-1"]
	if !strings.Contains(run(t, "docker", "logs", w.stub), "dns "+nonce+".dns.sandprobe.test") {
		t.Errorf("the local resolver never saw this run's EGR-1 query (%s)", nonce)
	}
	for _, rc := range r.Evidence.Receipts {
		if rc.Nonce == nonce {
			t.Errorf("the canary got EGR-1's query, so the resolver forwarded it: %+v", rc)
		}
	}
	expectResults(map[string]string{"EGR-1": obs.NotFound})(t, w, r)
}

// With the canary down, no network result counts: every canary check is unknown, never a pass or not_found.
func expectCanaryUnknown(t *testing.T, w world, r *Run) {
	for _, o := range r.Report.Outcomes {
		if ck, _ := catalog.Get(o.ID); ck.Canary != nil && o.Result != obs.Unknown {
			t.Errorf("%s with the canary down: want unknown, got %+v", o.ID, o)
		}
	}
	if r.Report.Complete {
		t.Error("the canary down: the run can't be complete")
	}
}

// A refusal the kernel never saw: with the canary working, every direct TCP check unknown, for the evidence reason
// this fault leaves, never a pass.
func expectNoDirectPass(reason string) func(t *testing.T, w world, r *Run) {
	return func(t *testing.T, w world, r *Run) {
		canaryWorked(t, r)
		for _, id := range directTCP {
			if o := outcome(r.Report, id); o.Result != obs.Unknown || !strings.Contains(o.Reason, reason) {
				t.Errorf("%s from a faked connect: want unknown because %q, got %+v", id, reason, o)
			}
		}
	}
}

// A process of the agent's own user: SEC-2 reads its environment, a proof; SEC-5 tests it, either way, never scoped out.
func expectPeer(t *testing.T, w world, r *Run) {
	if o := outcome(r.Report, "SEC-2"); o.Result != obs.Finding || o.Variant != "readable" || o.Class != catalog.Proof {
		t.Errorf("SEC-2 beside a same-user process: want a readable finding, a proof; got %+v", o)
	}
	if o := outcome(r.Report, "SEC-5"); o.Result != obs.Pass && o.Result != obs.Finding {
		t.Errorf("SEC-5 beside a same-user process: want it tested (pass or finding), got %+v", o)
	}
}

// Control sockets and a control port the agent may not even reach: indicators, never proofs, and never CHN-2.
func expectSockets(t *testing.T, w world, r *Run) {
	for id, v := range map[string]string{"AMP-4": "control_socket", "AMP-5": "control_port"} {
		if o := outcome(r.Report, id); o.Result != obs.Finding || o.Variant != v || o.Class != catalog.Indicator {
			t.Errorf("%s: want a %s finding, an indicator, got %+v", id, v, o)
		}
	}
	for _, n := range r.Report.Notes {
		if strings.HasPrefix(n, "CHN-2") {
			t.Errorf("an indicator must never make CHN-2: %s", n)
		}
	}
	// The conditions themselves, checked from the fixture's side (never by the probe, which connects to no local
	// socket or port it didn't create): the socket's server turns the agent away and serves root; the owner-match rule
	// stops the agent reaching the port while root still can.
	box := r.Box.ID()
	ask := `my $c = IO::Socket::UNIX->new(Type => SOCK_STREAM(), Peer => "/run/podman/podman.sock") or die $!; print scalar <$c>`
	for user, want := range map[string]string{"agent": "denied", "root": "ok"} {
		if got := strings.TrimSpace(run(t, "docker", "exec", "-u", user, box, "perl", "-MIO::Socket::UNIX", "-e", ask)); got != want {
			t.Errorf("the podman socket's server to %s: want %q, got %q", user, want, got)
		}
	}
	dial := `IO::Socket::INET->new(PeerAddr => "127.0.0.1:2375", Timeout => 2) or exit 1`
	if exec.Command("docker", "exec", "-u", "agent", box, "perl", "-MIO::Socket::INET", "-e", dial).Run() == nil {
		t.Error("the agent reached the control port the owner-match rule blocks")
	}
	if err := exec.Command("docker", "exec", "-u", "root", box, "perl", "-MIO::Socket::INET", "-e", dial).Run(); err != nil {
		t.Errorf("root should still reach the control port: %v", err)
	}
}

// deceptive is a deceptive case on its own network options.
func deceptive(mode string, expect func(t *testing.T, w world, r *Run), opts ...string) fixture {
	return fixture{name: "deceptive-" + mode, image: "deceptive", settle: time.Second, expect: expect,
		opts: func(world) []string { return append([]string{"-e", "DECEPTIVE=" + mode}, opts...) }}
}

// boxHas looks inside a running box for a file. Not being able to look fails the test.
func boxHas(t *testing.T, box, path string) bool {
	t.Helper()
	out, err := exec.Command("docker", "exec", box, "sh", "-c", `if [ -e "$1" ]; then echo present; else echo absent; fi`, "sh", path).Output()
	switch got := strings.TrimSpace(string(out)); {
	case err != nil:
		t.Fatalf("can't look for %s in %s: %v", path, box, err)
	case got == "present":
		return true
	case got != "absent":
		t.Fatalf("looking for %s: %q", path, got)
	}
	return false
}

// neverAorB: a box that deceives is never graded A or B.
func neverAorB(t *testing.T, r *Run) {
	if r.Report.Letter == "A" || r.Report.Letter == "B" {
		t.Errorf("a deceiving box graded %s", r.Report.Letter)
	}
}

func expectAMP1Deceived(result, variant string) func(t *testing.T, w world, r *Run) {
	return func(t *testing.T, w world, r *Run) {
		neverAorB(t, r)
		if o := outcome(r.Report, "AMP-1"); o.Result != result || o.Variant != variant {
			t.Errorf("AMP-1: want %s %s, got %+v", result, variant, o)
		}
		for _, s := range []string{"linked", "writable", "onpath", "prompt"} {
			if boxHas(t, r.Box.ID(), "/tmp/sentinel-"+s) {
				t.Errorf("a sudo shim ran (%s)", s)
			}
		}
	}
}

// No sudo qualifies: the fixed path a link to a shim, a shim in a directory the agent writes, one on PATH. AMP-1 is
// unknown, never absent, and no shim runs.
var expectSudoShims = expectAMP1Deceived(obs.Unknown, "")

// The box's curl is never run, and the secret its link points at is never opened.
func expectCurlUntouched(t *testing.T, w world, r *Run) {
	if boxHas(t, r.Box.ID(), "/tmp/sentinel-curl") {
		t.Error("the box's curl ran")
	}
	log := run(t, "docker", "exec", r.Box.ID(), "cat", "/tmp/secret-access.log")
	if strings.TrimSpace(log) != "" {
		t.Errorf("a fake secret was opened:\n%s", log)
	}
}

// Preloaded libraries that fail every dynamically linked connect: the probe is static, so its results are its own.
func expectPreload(t *testing.T, w world, r *Run) {
	canaryWorked(t, r)
	dial := `IO::Socket::INET->new(PeerAddr => "` + w.canaryIP + `:443", Timeout => 2) or exit 1`
	if exec.Command("docker", "exec", "-u", "agent", r.Box.ID(), "perl", "-MIO::Socket::INET", "-e", dial).Run() == nil {
		t.Fatal("the preload isn't in effect: a dynamically linked connect got out")
	}
	expectResults(map[string]string{"EGR-2": obs.Finding})(t, w, r)
}

// A proxy that refuses every tunnel while direct egress is open: EGR-3 not_found (it asked, and the proxy said no),
// EGR-2 found, and the proxy saw this run's CONNECT to the canary.
func expectProxy403(t *testing.T, w world, r *Run) {
	canaryWorked(t, r)
	if !strings.Contains(run(t, "docker", "logs", w.stub), `proxy "CONNECT `+r.Manifest.Endpoints["EGR-3"]+` HTTP/1.1"`) {
		t.Error("the proxy never saw this run's CONNECT")
	}
	expectResults(map[string]string{"EGR-3": obs.NotFound, "EGR-2": obs.Finding})(t, w, r)
}

// A proxy URL holding credentials: EGR-3 unknown, and the credentials never leave the box, never in the plan, the
// survey or any document.
func expectProxyCreds(t *testing.T, w world, r *Run) {
	if o := outcome(r.Report, "EGR-3"); o.Result != obs.Unknown {
		t.Errorf("EGR-3 with a credentialed proxy: want unknown, got %+v", o)
	}
	if strings.Contains(run(t, "docker", "logs", w.stub), "sandprobe-fake") {
		t.Error("the proxy's credentials reached the proxy")
	}
	for name, v := range map[string]any{"survey": r.Survey, "manifest": r.Manifest, "input": r.Input, "report": r.Report} {
		if b, _ := json.Marshal(v); bytes.Contains(b, []byte("sandprobe-fake")) {
			t.Errorf("the proxy's credentials are in the %s", name)
		}
	}
}

// TLS to the canary rewritten to a server with its own key: EGR-4 found, and EGR-2 never passes through it.
func expectIntercepted(t *testing.T, w world, r *Run) {
	canaryWorked(t, r)
	neverAorB(t, r)
	if o := outcome(r.Report, "EGR-4"); o.Result != obs.Finding || o.Variant != "intercepted" {
		t.Errorf("EGR-4: want the interception found, got %+v", o)
	}
	if o := outcome(r.Report, "EGR-2"); o.Result != obs.Unknown || !strings.Contains(o.Reason, "TLS interception on this route") {
		t.Errorf("EGR-2 through an interceptor: want unknown because of the interception, got %+v", o)
	}
}

func noNet(world) []string { return []string{"--network", "none"} }

func dockerQuiet(ctx context.Context, args ...string) {
	exec.CommandContext(ctx, "docker", args...).Run()
}

func hooked(h func(ctx context.Context, stage string, d *DockerBox)) func(d *DockerBox) Box {
	return func(d *DockerBox) Box { d.Hook = h; return d }
}

// cleaner deletes the markers in root once the new box is up, before the recheck, and nothing else.
func cleaner(root string) func(ctx context.Context, stage string, d *DockerBox) {
	return func(ctx context.Context, stage string, d *DockerBox) {
		if stage == "created" {
			dockerQuiet(ctx, "exec", "-u", "root", d.Container, "sh", "-c", "rm -f "+root+"/.sandprobe-*")
		}
	}
}

// substitute replaces each marker in root with an unrelated file holding the same run id (a new inode, by rename),
// and watches it for any open, so the fixture can see it's never read.
func substitute(root string) func(ctx context.Context, stage string, d *DockerBox) {
	return func(ctx context.Context, stage string, d *DockerBox) {
		if stage != "created" {
			return
		}
		dockerQuiet(ctx, "exec", "-u", "root", d.Container, "sh", "-c",
			`for f in `+root+`/.sandprobe-*; do cp "$f" "$f.new" && chown agent:agent "$f.new" && mv "$f.new" "$f"; done`)
		dockerQuiet(ctx, "exec", "-d", "-u", "root", d.Container, "sh", "-c",
			`inotifywait -q -m -e open,access -o /tmp/substitute-access.log `+root+`/.sandprobe-*`)
		time.Sleep(500 * time.Millisecond)
	}
}

// restartBox is a restore-in-place reset that isn't one: docker restart, the same box, no checkpoint named.
type restartBox struct {
	*DockerBox
	mounts []string
	fail   bool
}

func restarted(fail bool, mounts ...string) func(d *DockerBox) Box {
	return func(d *DockerBox) Box { return &restartBox{DockerBox: d, mounts: mounts, fail: fail} }
}

func (b *restartBox) Storage(context.Context) (Storage, error) {
	return Storage{Model: "restore", Mounts: b.mounts}, nil
}

func (b *restartBox) Reset(ctx context.Context) (Box, *obs.ResetEvidence, error) {
	err := exec.CommandContext(ctx, "docker", "restart", b.Container).Run()
	return b, &obs.ResetEvidence{Model: "restore", OperationID: token("op"), Done: err == nil && !b.fail,
		BoxBefore: b.Container, BoxAfter: b.Container}, err
}

func expectPER5(result, why string) func(t *testing.T, w world, r *Run) {
	return func(t *testing.T, w world, r *Run) {
		if o := outcome(r.Report, "PER-5"); o.Result != result || !strings.Contains(o.Reason+o.Evidence, why) {
			t.Errorf("PER-5: want %s because %q, got %+v", result, why, o)
		}
	}
}

// The substitute is never read, and is still there: nothing is ever removed by name.
func expectSubstitute(t *testing.T, w world, r *Run) {
	expectPER5(obs.Unknown, "a file at the marker's name isn't the placed marker; unread")(t, w, r)
	if log := run(t, "docker", "exec", r.Box.ID(), "cat", "/tmp/substitute-access.log"); strings.TrimSpace(log) != "" {
		t.Errorf("the substitute was opened:\n%s", log)
	}
	if out := run(t, "docker", "exec", r.Box.ID(), "sh", "-c", "ls /home/agent/persist/.sandprobe-* | wc -l"); strings.TrimSpace(out) != "1" {
		t.Errorf("the file at the marker's name is gone: something removed it by name (%s)", out)
	}
}

// A restart standing in for a restore: the marker survives, but with no checkpoint named nothing is proven. Home,
// declared as a mount too, is one root with one marker.
func expectRestart(t *testing.T, w world, r *Run) {
	expectPER5(obs.Unknown, "checkpoint")(t, w, r)
	n := 0
	for _, pm := range r.Manifest.Marks {
		if pm.Root == "/home/agent" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("home, reached as home and as a declared mount: want one marker, got %d (%+v)", n, r.Manifest.Marks)
	}
}

func localProxy(w world) []string {
	return []string{"--network", w.network, "--dns", w.canaryIP, "-e", "EFFECTS=proxy", "-e", "HTTPS_PROXY=http://127.0.0.1:3129"}
}

// boxFile reads a file inside a running box; not being able to read it fails the test.
func boxFile(t *testing.T, box, path string) string {
	t.Helper()
	return strings.TrimSpace(run(t, "docker", "exec", box, "cat", path))
}

// Nothing under home or /etc changed, the FIFO at a credential path was never opened, no pre-existing loopback
// service (one on a control port) heard from the probe, and SEC-3 is unknown, never a pass or an absence.
func expectUntouched(t *testing.T, w world, r *Run) {
	box := r.Box.ID()
	if log := boxFile(t, box, "/tmp/fs.log"); log != "" {
		t.Errorf("home or /etc changed:\n%s", log)
	}
	if log := boxFile(t, box, "/tmp/fifo.log"); log != "" {
		t.Errorf("the FIFO at a credential path was opened:\n%s", log)
	}
	if log := boxFile(t, box, "/tmp/services.log"); log != "" {
		t.Errorf("a pre-existing loopback service was contacted:\n%s", log)
	}
	if o := outcome(r.Report, "SEC-3"); o.Result != obs.Unknown || !strings.Contains(o.Reason, "/home/agent/.netrc isn't a regular file") {
		t.Errorf("SEC-3 with a FIFO at ~/.netrc: want unknown because it isn't a regular file, got %+v", o)
	}
	// The positive control, after the logs were seen empty: every watcher and service was up and recording, so an
	// empty log meant nothing happened, not that nothing was listening.
	dial := `for my $p (2376, 8125) { IO::Socket::INET->new(PeerAddr => "127.0.0.1:$p", Timeout => 2) or die "port $p: $!" }`
	run(t, "docker", "exec", box, "perl", "-MIO::Socket::INET", "-e", dial)
	run(t, "docker", "exec", box, "sh", "-c", "touch /home/agent/.control /etc/.control && exec 3<>/home/agent/.netrc")
	time.Sleep(300 * time.Millisecond)
	for path, want := range map[string][]string{
		"/tmp/services.log": {"2376 connected", "8125 connected"},
		"/tmp/fs.log":       {"/home/agent/ ", "/etc/ "},
		"/tmp/fifo.log":     {"OPEN"},
	} {
		log := boxFile(t, box, path)
		for _, w := range want {
			if !strings.Contains(log, w) {
				t.Errorf("control: %s doesn't record %q, so it wasn't watching: %q", path, w, log)
			}
		}
	}
}

// A dangling link at a credential path is unknown, never absent.
func expectSEC3Dangling(t *testing.T, w world, r *Run) {
	if o := outcome(r.Report, "SEC-3"); o.Result != obs.Unknown || !strings.Contains(o.Reason, "dangling") {
		t.Errorf("SEC-3 with a dangling link: want unknown because it's dangling, got %+v", o)
	}
}

// A local proxy: without approval EGR-3 is skipped and listed, and the proxy hears nothing; with it, exactly one
// CONNECT, to the canary.
func expectLocalProxy(approved bool) func(t *testing.T, w world, r *Run) {
	return func(t *testing.T, w world, r *Run) {
		log := boxFile(t, r.Box.ID(), "/tmp/proxy.log")
		if !approved {
			if !strings.Contains(r.Report.Skipped["EGR-3"], "local") || log != "" {
				t.Errorf("unapproved: want EGR-3 skipped as local and the proxy untouched; skipped %q, log %q", r.Report.Skipped["EGR-3"], log)
			}
			return
		}
		canaryWorked(t, r)
		if want := "CONNECT " + r.Manifest.Endpoints["EGR-3"] + " HTTP/1.1"; log != want {
			t.Errorf("approved: want exactly one %q, got %q", want, log)
		}
		expectResults(map[string]string{"EGR-3": obs.NotFound})(t, w, r)
	}
}

// SBX-10's stated limit: a substitute reporting the shipped digest and fabricating every proof is graded as if it were
// the probe. On the holes box, open to the canary and full of findings, it earns A. The only outside evidence, the
// canary's receipts, shows nothing here because the liar never connects. The report's "host-shipped, never attested"
// label and SBX-10's boundary beside the grade come with the report layer (OUT-1, OUT-2, GRD-4).
func expectSubstituted(t *testing.T, w world, r *Run) {
	if !r.Report.Valid || r.Report.Letter != "A" {
		t.Fatalf("want the substitution undetected (SBX-10): a valid A, got valid=%v %s %s", r.Report.Valid, r.Report.Letter, r.Report.Invalid)
	}
	// What was forged: the canary worked, EGR-2 was asked and passed, yet the route is open (a connect from the box
	// gets through, checked from the fixture's side) and the canary holds no receipt for EGR-2's nonce.
	canaryWorked(t, r)
	if !slices.Contains(r.Manifest.Selected, "EGR-2") || outcome(r.Report, "EGR-2").Result != obs.Pass {
		t.Fatalf("want EGR-2 selected and passed on a forged proof, got %+v", outcome(r.Report, "EGR-2"))
	}
	dial := `IO::Socket::INET->new(PeerAddr => "` + w.canaryIP + `:443", Timeout => 2) or exit 1`
	if err := exec.Command("docker", "exec", "-u", "agent", r.Box.ID(), "perl", "-MIO::Socket::INET", "-e", dial).Run(); err != nil {
		t.Fatalf("the route to the canary must be open for the pass to be a forgery: %v", err)
	}
	for _, rc := range r.Evidence.Receipts {
		if rc.Nonce == r.Manifest.CheckNonces["EGR-2"] {
			t.Fatalf("the canary has EGR-2's nonce, so the substitute connected: %+v", rc)
		}
	}
	t.Logf("recorded, as SBX-10 says: a substituted probe on an open box graded %s, undetected", r.Report.Letter)
}

// The exported fixtures: each run is checked for the shape the public tests rely on, then, when
// SANDPROBE_WRITE_FIXTURES names a directory, saved there as a bundle: the manifest, the probe's own observations and
// the canary's evidence, exactly as this run produced them. internal/report builds test/reports from the bundles.
func exportBundle(t *testing.T, name string, r *Run) {
	t.Helper()
	dir := os.Getenv("SANDPROBE_WRITE_FIXTURES")
	if dir == "" {
		return
	}
	b, err := json.MarshalIndent(struct {
		Manifest     obs.Manifest       `json:"manifest"`
		Observations string             `json:"observations"`
		Evidence     obs.CanaryEvidence `json:"evidence"`
	}{r.Manifest, string(r.Doc), r.Evidence}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".bundle.json"), append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Root, with every route out to the canary open: all six canary routes deliver.
func exportOpen(t *testing.T, w world, r *Run) {
	canaryWorked(t, r)
	expectResults(map[string]string{"EGR-1": obs.Finding, "EGR-2": obs.Finding, "EGR-5.22": obs.Finding, "EGR-5.80": obs.Finding,
		"EGR-5.8080": obs.Finding, "EGR-5.53u": obs.Finding, "AMP-2": obs.Finding, "AMP-3": obs.Pass})(t, w, r)
	exportBundle(t, "egress-open", r)
}

// Root, with every TCP port to the canary refused and UDP to it rejected: four TCP refusals proven, and DNS and UDP
// silent, which proves nothing.
func exportRefused(t *testing.T, w world, r *Run) {
	canaryWorked(t, r)
	expectResults(map[string]string{"EGR-2": obs.Pass, "EGR-5.22": obs.Pass, "EGR-5.80": obs.Pass, "EGR-5.8080": obs.Pass,
		"AMP-2": obs.Finding, "AMP-3": obs.Pass})(t, w, r)
	for _, id := range []string{"EGR-1", "EGR-5.53u"} {
		if o := outcome(r.Report, id); o.Result == obs.Pass || o.Result == obs.Finding {
			t.Errorf("%s: silence must prove nothing, got %+v", id, o)
		}
	}
	exportBundle(t, "egress-refused", r)
}

// The canary paused: no canary result counts, and the run is incomplete.
func exportCanaryDown(t *testing.T, w world, r *Run) {
	expectCanaryUnknown(t, w, r)
	exportBundle(t, "canary-down", r)
}
