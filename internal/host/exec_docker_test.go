package host

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"sandprobe/internal/canary"
	"sandprobe/internal/catalog"
	"sandprobe/internal/grade"
	"sandprobe/internal/obs"
	"sandprobe/internal/probes"
)

// PRV-15 end to end with the shipped probe, through `docker exec -i <container> sh` into a container running as
// nobody: the preflight binds nobody, the survey runs, a command that switches to root is refused at the probe's
// startup with nothing written, and no scratch path is left in the box.
func TestExecBoxDocker(t *testing.T) {
	if os.Getenv("SANDPROBE_FIXTURES") == "" {
		t.Skip("set SANDPROBE_FIXTURES=1 to run against Docker")
	}
	ctx := context.Background()
	archOut, err := exec.Command("docker", "info", "--format", "{{.Architecture}}").Output()
	if err != nil {
		t.Fatal(err)
	}
	arch := map[string]string{"x86_64": "amd64", "aarch64": "arm64"}[strings.TrimSpace(string(archOut))]
	bin, _, err := probes.Probe(arch)
	if err != nil {
		t.Fatal(err)
	}
	const image = "debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2"
	id, err := exec.Command("docker", "run", "-d", "--rm", "--network", "none", "--user", "65534:65534", image, "sleep", "300").Output()
	if err != nil {
		t.Fatal(err)
	}
	ctr := strings.TrimSpace(string(id))
	defer exec.Command("docker", "rm", "-f", ctr).Run()

	b, err := NewExecBox([]string{"docker", "exec", "-i", ctr, "sh"}, bin, "")
	if err != nil {
		t.Fatal(err)
	}
	if w, err := b.Preflight(ctx, "nobody"); err != nil || w.UIDs != [4]int{65534, 65534, 65534, 65534} {
		t.Fatalf("preflight: %+v %v", w, err)
	}
	out, err := b.Probe(ctx, []string{"-survey"}, nil)
	if err != nil {
		t.Fatalf("survey: %v", err)
	}
	if _, err := obs.ParseSurvey(out); err != nil {
		t.Fatalf("the survey didn't parse: %v", err)
	}
	if _, err := (&ExecBox{Command: b.Command, Binary: bin, Scratch: b.Scratch}).Preflight(ctx, "root"); err == nil {
		t.Fatal("a preflight for root passed in a box running as nobody")
	}

	// The box's command now runs as root: the bound probe refuses at startup and writes nothing.
	b.Command = []string{"docker", "exec", "-i", "-u", "0", ctr, "sh"}
	if out, err := b.Probe(ctx, []string{"-survey"}, nil); err == nil || len(out) != 0 {
		t.Fatalf("a probe bound to nobody ran as root: %q %v", out, err)
	}
	if err := b.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	left, _ := exec.Command("docker", "exec", ctr, "sh", "-c", "ls -d /tmp/sandprobe-* 2>/dev/null | wc -l").Output()
	if strings.TrimSpace(string(left)) != "0" {
		t.Fatalf("scratch left in the box: %s", left)
	}
}

// PRV-15 through the whole run: Execute drives the shipped probe in a nobody container through docker exec, the
// upload survives base64 (SBX-5's digest matches), the run grades valid, the provider-endpoint checks are skipped with
// PRV-15's reason, PER-5 is skipped on an existing box, and no scratch is left behind.
func TestExecuteThroughExecBox(t *testing.T) {
	if os.Getenv("SANDPROBE_FIXTURES") == "" {
		t.Skip("set SANDPROBE_FIXTURES=1 to run against Docker")
	}
	ctx := context.Background()
	archOut, _ := exec.Command("docker", "info", "--format", "{{.Architecture}}").Output()
	arch := map[string]string{"x86_64": "amd64", "aarch64": "arm64"}[strings.TrimSpace(string(archOut))]
	bin, sum, err := probes.Probe(arch)
	if err != nil {
		t.Fatal(err)
	}
	const image = "debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2"
	id, err := exec.Command("docker", "run", "-d", "--rm", "--network", "none", "--user", "65534:65534", image, "sleep", "300").Output()
	if err != nil {
		t.Fatal(err)
	}
	ctr := strings.TrimSpace(string(id))
	defer exec.Command("docker", "rm", "-f", ctr).Run()
	b, err := NewExecBox([]string{"docker", "exec", "-i", ctr, "sh"}, bin, "")
	if err != nil {
		t.Fatal(err)
	}
	if a, err := b.Arch(ctx); err != nil || a != arch {
		t.Fatalf("arch %q %v", a, err)
	}
	if _, err := b.Preflight(ctx, "nobody"); err != nil {
		t.Fatal(err)
	}
	var armed []canary.Want
	c := &fakeCanary{answer: func(q canary.Request) canary.Answer {
		if q.Op == "arm" {
			armed = q.Wants
		}
		return whole(q, armed)
	}}
	r, err := Execute(ctx, b, c, Options{Mode: "exec", ProbeSHA256: sum, Excluded: ExecExclusions()})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Report.Valid {
		t.Fatalf("the run isn't valid: %s", r.Report.Invalid)
	}
	for _, id := range []string{"SEC-4", "EGR-3", "AMP-6", "AMP-7", "PER-5"} {
		if r.Manifest.Skipped[id] == "" {
			t.Errorf("%s wasn't skipped", id)
		}
	}
	if !strings.Contains(r.Manifest.Skipped["SEC-4"], "PRV-15") {
		t.Errorf("SEC-4's reason: %q", r.Manifest.Skipped["SEC-4"])
	}
	if err := b.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	left, _ := exec.Command("docker", "exec", ctr, "sh", "-c", "ls -d /tmp/sandprobe-* 2>/dev/null | wc -l").Output()
	if strings.TrimSpace(string(left)) != "0" {
		t.Fatalf("scratch left in the box: %s", left)
	}
}

// HCN-5 end to end: the shipped probe through docker exec, without a canary. The run is valid, every canary check is
// unknown with the host's reason, no canary is asked anything, and nothing is left in the box.
func TestExecuteThroughExecBoxNoCanary(t *testing.T) {
	if os.Getenv("SANDPROBE_FIXTURES") == "" {
		t.Skip("set SANDPROBE_FIXTURES=1 to run against Docker")
	}
	ctx := context.Background()
	archOut, _ := exec.Command("docker", "info", "--format", "{{.Architecture}}").Output()
	arch := map[string]string{"x86_64": "amd64", "aarch64": "arm64"}[strings.TrimSpace(string(archOut))]
	bin, sum, err := probes.Probe(arch)
	if err != nil {
		t.Fatal(err)
	}
	const image = "debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2"
	id, err := exec.Command("docker", "run", "-d", "--rm", "--user", "65534:65534", image, "sleep", "300").Output()
	if err != nil {
		t.Fatal(err)
	}
	ctr := strings.TrimSpace(string(id))
	defer exec.Command("docker", "rm", "-f", ctr).Run()
	b, err := NewExecBox([]string{"docker", "exec", "-i", ctr, "sh"}, bin, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Preflight(ctx, "nobody"); err != nil {
		t.Fatal(err)
	}
	c := &fakeCanary{answer: func(q canary.Request) canary.Answer { t.Errorf("asked the canary %s", q.Op); return canary.Answer{} }}
	r, err := Execute(ctx, b, c, Options{Mode: "exec", ProbeSHA256: sum, Excluded: ExecExclusions(), NoCanary: true})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Report.Valid || r.Report.Complete || len(c.asks) != 0 {
		t.Fatalf("valid %v (%s), complete %v, asks %v", r.Report.Valid, r.Report.Invalid, r.Report.Complete, c.asks)
	}
	for _, o := range r.Report.Outcomes {
		if ck, _ := catalog.Get(o.ID); catalog.NeedsCanary(ck) && (o.Result != obs.Unknown || o.Reason != grade.NoCanaryReason) {
			t.Errorf("%s: %s %q", o.ID, o.Result, o.Reason)
		}
	}
	if r.Report.Skipped["EGR-3"] != ExecExclusions()["EGR-3"] {
		t.Errorf("EGR-3 lost its provider-endpoint skip: %q", r.Report.Skipped["EGR-3"])
	}
	if err := b.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
}

// RCP-1 to RCP-3 end to end: a recipe that makes a Docker container (ID-addressed) runs the shipped probe through its
// sp_shell, grades without a canary, and deletes the container by the ID its create returned, confirmed gone.
func TestRecipeThroughDocker(t *testing.T) {
	if os.Getenv("SANDPROBE_FIXTURES") == "" {
		t.Skip("set SANDPROBE_FIXTURES=1 to run against Docker")
	}
	ctx := context.Background()
	const image = "debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2"
	r, err := ParseRecipe("docker-test", []byte(`# sandprobe-recipe: v1
# provider: local Docker, for the runner's own test
# terms: none: a local container
# exclusions: SEC-4 EGR-3 AMP-6 AMP-7
# addressed-by: id
sp_ready() { docker info >/dev/null 2>&1 && echo "local docker"; }
sp_create() { docker run -d --user 65534:65534 `+image+` sleep 300; }
sp_shell() { exec docker exec -i "$SANDPROBE_BOX" sh; }
sp_delete() { docker rm -f "$SANDPROBE_BOX" >/dev/null; }
sp_gone() { docker inspect "$SANDPROBE_BOX" >/dev/null 2>&1 && return 1; docker info >/dev/null 2>&1 || return 2; return 0; }
`))
	if err != nil {
		t.Fatal(err)
	}
	target, err := r.Ready(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewRecipeBox(r, target, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Create(ctx); err != nil {
		t.Fatal(err)
	}
	defer exec.Command("docker", "rm", "-f", b.BoxID).Run()
	arch, err := b.Arch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	bin, sum, err := probes.Probe(arch)
	if err != nil {
		t.Fatal(err)
	}
	b.Binary = bin
	if _, err := b.Preflight(ctx, "nobody"); err != nil {
		t.Fatal(err)
	}
	excl := map[string]string{}
	for _, id := range r.Exclusions {
		excl[id] = "test"
	}
	run, err := Execute(ctx, b, nil, Options{Mode: "exec", ProbeSHA256: sum, Excluded: excl, NoCanary: true})
	if err != nil {
		t.Fatal(err)
	}
	if !run.Report.Valid || run.Report.Skipped["PER-5"] == "" {
		t.Fatalf("valid %v (%s), PER-5 skip %q", run.Report.Valid, run.Report.Invalid, run.Report.Skipped["PER-5"])
	}
	if err := b.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.Delete(ctx); err != nil {
		t.Fatal(err)
	}
	if exec.Command("docker", "inspect", b.BoxID).Run() == nil {
		t.Fatal("the container is still there")
	}
}

// LNC-1 to LNC-4 end to end, the reproduction that turned every run exec red: a debian:bookworm-slim box (dash is its
// sh) with an agent user, reached as the agent through docker exec. The shell execs the wrapper, so SEC-2 and SEC-5
// pass with twin proof and name the wrapper they skipped; a same-uid decoy is still a finding; and a name dash drops
// from the person's docker exec never reaches the wrapper, so the run still passes. No scratch is left behind.
func TestExecWrapper(t *testing.T) {
	if os.Getenv("SANDPROBE_FIXTURES") == "" {
		t.Skip("set SANDPROBE_FIXTURES=1 to run against Docker")
	}
	ctx := context.Background()
	archOut, _ := exec.Command("docker", "info", "--format", "{{.Architecture}}").Output()
	arch := map[string]string{"x86_64": "amd64", "aarch64": "arm64"}[strings.TrimSpace(string(archOut))]
	bin, sum, err := probes.Probe(arch)
	if err != nil {
		t.Fatal(err)
	}
	const image = "debian:bookworm-slim@sha256:e67eeead736ff7bbe258ef088bff683635c561b1fcfefad0806c1df4ab49ce0e"
	id, err := exec.Command("docker", "run", "-d", "--rm", "--network", "none", image, "sleep", "600").Output()
	if err != nil {
		t.Fatal(err)
	}
	ctr := strings.TrimSpace(string(id))
	defer exec.Command("docker", "rm", "-f", ctr).Run()
	if out, err := exec.Command("docker", "exec", ctr, "useradd", "-m", "-u", "1000", "agent").CombinedOutput(); err != nil {
		t.Fatalf("useradd: %v %s", err, out)
	}
	yama, _ := exec.Command("docker", "exec", ctr, "sh", "-c", "cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null").Output()
	scope := strings.TrimSpace(string(yama))

	run := func(command ...string) map[string]obs.Observation {
		t.Helper()
		b, err := NewExecBox(command, bin, "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := b.Preflight(ctx, "agent"); err != nil {
			t.Fatal(err)
		}
		c := &fakeCanary{answer: func(q canary.Request) canary.Answer { t.Errorf("asked the canary %s", q.Op); return canary.Answer{} }}
		r, err := Execute(ctx, b, c, Options{Mode: "exec", ProbeSHA256: sum, Excluded: ExecExclusions(), NoCanary: true})
		if err != nil {
			t.Fatal(err)
		}
		if !r.Report.Valid {
			t.Fatalf("invalid run: %s", r.Report.Invalid)
		}
		if err := b.Cleanup(ctx); err != nil {
			t.Fatal(err)
		}
		d, err := obs.ParseDoc(r.Doc)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]obs.Observation{}
		for _, o := range d.Observations {
			got[o.ID] = o
		}
		for _, o := range r.Report.Outcomes { // the grader's word decides the result; the raw observation shows the proof
			if o.ID == "SEC-2" || o.ID == "SEC-5" {
				ob := got[o.ID]
				ob.Result = o.Result
				got[o.ID] = ob
			}
		}
		return got
	}
	shell := []string{"docker", "exec", "-i", "-u", "agent", ctr, "sh"}

	// The box alone: a pass, with twin proof, naming the wrapper it skipped.
	for id, o := range run(shell...) {
		if (id == "SEC-2" || id == "SEC-5") && (o.Result != obs.Pass || o.Proof == nil || !o.Proof.Twin || !strings.Contains(o.Reason, "Sandprobe's own wrapper, PID ")) {
			t.Errorf("box alone, %s: %+v %+v", id, o, o.Proof)
		}
	}
	// A name dash drops from the person's own docker exec never reaches the wrapper: still a pass.
	for id, o := range run("docker", "exec", "-i", "-u", "agent", "-e", "MY-KEY=sandprobe-fake", ctr, "sh") {
		if (id == "SEC-2" || id == "SEC-5") && o.Result != obs.Pass {
			t.Errorf("MY-KEY given, %s: %+v", id, o)
		}
	}
	// A same-uid decoy is still a finding, on its own PID, never the wrapper's.
	if err := exec.Command("docker", "exec", "-d", "-u", "agent", ctr, "sh", "-c", "echo $$ > /tmp/decoy.pid; exec sleep 300").Run(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	pid, _ := exec.Command("docker", "exec", ctr, "cat", "/tmp/decoy.pid").Output()
	decoy := "/proc/" + strings.TrimSpace(string(pid)) + "/"
	for id, o := range run(shell...) {
		want := id == "SEC-2" || id == "SEC-5" && (scope == "" || scope == "0") // Yama 1 refuses a non-descendant's memory
		if want && (o.Result != obs.Finding || !strings.Contains(o.Evidence, decoy)) {
			t.Errorf("decoy %s, %s: %+v", decoy, id, o)
		}
	}
	left, _ := exec.Command("docker", "exec", ctr, "sh", "-c", "ls -d /tmp/sandprobe-* 2>/dev/null | wc -l").Output()
	if strings.TrimSpace(string(left)) != "0" {
		t.Fatalf("scratch left in the box: %s", left)
	}
}
