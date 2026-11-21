package host

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

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
