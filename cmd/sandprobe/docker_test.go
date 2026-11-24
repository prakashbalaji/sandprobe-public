package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// PRV-14: the person's options pass through unchanged; Sandprobe's network and resolver only when they name none.
func TestDockerBoxArgs(t *testing.T) {
	own := boxArgs("net1", "172.30.100.10", "/tmp/p", "img", []string{"--read-only"})
	if !slices.Equal(own, []string{"run", "-d", "--network", "net1", "--dns", "172.30.100.10", "--read-only",
		"--entrypoint", dockerProbePath, "--init=false", "--tmpfs", dockerScratchSpec,
		"-v", "/tmp/p:" + dockerProbePath + ":ro", "img", "-idle"}) {
		t.Errorf("no network named: %q", own)
	}
	for _, opts := range [][]string{{"--network", "none"}, {"--network=host"}, {"--net", "bridge"}, {"--net=none"}} {
		args := boxArgs("net1", "172.30.100.10", "/tmp/p", "img", opts)
		if slices.Contains(args, "net1") || slices.Contains(args, "--dns") || !slices.Equal(args[2:2+len(opts)], opts) {
			t.Errorf("%q: the person's network must stand, unchanged: %q", opts, args)
		}
	}
}

// Options after "--" are for a docker run only, and never reach any other command.
func TestPassthroughOnlyForDocker(t *testing.T) {
	for _, args := range [][]string{{"run", "sprites", "-y", "--", "--read-only"}, {"scorecard", "x.json", "--", "-v"}} {
		var out, errb bytes.Buffer
		if code := run(append(args, "-o", "json"), &out, &errb); code != exitUsage {
			t.Errorf("%q: want usage, got %d", args, code)
		}
	}
}

// The probe runs as -as, else the created container's own user (the person's --user, else the image's), else root:
// an option that overrides the image's user, either way, is the user graded (PR #40 review).
func TestProbeUser(t *testing.T) {
	for _, tc := range []struct{ as, container, want string }{
		{"", "app", "app"},      // a non-root image, nothing overridden
		{"", "0", "0"},          // a non-root image run --user 0: graded as root
		{"", "1000", "1000"},    // a root image run --user 1000: graded as 1000
		{"agent", "0", "agent"}, // -as wins
		{"", "", "root"},
	} {
		if got := probeUser(tc.as, tc.container); got != tc.want {
			t.Errorf("as %q, container %q: got %q, want %q", tc.as, tc.container, got, tc.want)
		}
	}
}

func TestDockerAutomaticRemovalCannotBypassOwnership(t *testing.T) {
	for _, option := range []string{"--rm", "--rm=true", "--rm=1"} {
		var out, errb bytes.Buffer
		if code := run([]string{"run", "docker", "unused-image", "-y", "--", option}, &out, &errb); code != exitUsage {
			t.Fatalf("%s: got %d, want refusal before Docker access", option, code)
		}
	}
	if automaticRemoval([]string{"--rm=false"}) {
		t.Fatal("disabled automatic removal rejected")
	}
}

func TestDockerAmbiguousNetworkCreateStopsWithoutRetry(t *testing.T) {
	for _, mode := range []string{"lost", "empty", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			log := filepath.Join(dir, "calls")
			script := `#!/bin/sh
printf '%s\n' "$*" >> "$SANDPROBE_NETWORK_LOG"
case "$*" in
 "info --format {{.Architecture}}") echo aarch64 ;;
 "image inspect"*) echo sha256:fixture ;;
 "network ls -q") echo existing-network ;;
 "network inspect"*) echo 172.30.100.0/24 ;;
 "network create"*)
  case "$SANDPROBE_NETWORK_OUTCOME" in
   timeout) exec sleep 60 ;;
   lost) exit 1 ;;
   empty) exit 0 ;;
  esac ;;
 *) exit 1 ;;
esac
`
			if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("SANDPROBE_NETWORK_LOG", log)
			t.Setenv("SANDPROBE_NETWORK_OUTCOME", mode)
			if mode == "timeout" {
				defer func(old time.Duration) { dockerRunTimeout = old }(dockerRunTimeout)
				dockerRunTimeout = 2 * time.Second
			}
			var out, errb bytes.Buffer
			code := run([]string{"run", "docker", "fixture", "-y"}, &out, &errb)
			calls, _ := os.ReadFile(log)
			if code != exitCleanup || strings.Count(string(calls), "network create ") != 1 || bytes.Contains(calls, []byte("network rm")) {
				t.Fatalf("ambiguous creation retried/deleted or silently cleaned: code%d calls%s", code, calls)
			}
			if !strings.Contains(errb.String(), "attempted sandprobe-") || !strings.Contains(errb.String(), "172.30.101.0/24") || strings.Contains(errb.String(), "nothing was created") {
				t.Fatal("lost attempted identity or overstated cleanup", errb.String())
			}
		})
	}
}

// A hung Docker can't stop the run from reaching its cleanup: the deadline kills the stuck call, and the canary and
// the network are still removed (PR #40 review). Docker here is a fake that hangs on starting the box.
func TestDockerHangReachesCleanup(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "calls.log")
	fake := `#!/bin/sh
echo "$*" >> "` + log + `"
case "$*" in
  "info --format {{.Architecture}}") echo aarch64 ;;
  "image inspect"*) echo sha256:fake ;;
  "network create"*) echo net0123456789abcdef ;;
  "run -d"*/sandprobe-canary:ro*) echo canary0123456789abcdef ;;
  "run -d"*) exec sleep 60 ;;
  "port "*) echo 127.0.0.1:40001 ;;
  "exec "*) echo '{"ok":true}' ;;
  "inspect --type container"*) echo "Error: No such container" >&2; exit 1 ;;
  "network inspect"*) echo "Error: network not found" >&2; exit 1 ;;
  *) ;;
esac
`
	os.WriteFile(filepath.Join(dir, "docker"), []byte(fake), 0o755)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	defer func(d time.Duration) { dockerRunTimeout = d }(dockerRunTimeout)
	dockerRunTimeout = 3 * time.Second
	start := time.Now()
	var out, errb bytes.Buffer
	code := run([]string{"run", "docker", "some-image", "-y", "-o", "json", "-out", t.TempDir()}, &out, &errb)
	if took := time.Since(start); took > 20*time.Second {
		t.Fatalf("a hung docker held the run for %s", took)
	}
	calls, _ := os.ReadFile(log)
	if code == 0 || !bytes.Contains(calls, []byte("rm -f -v canary0123456789abcdef")) || !bytes.Contains(calls, []byte("network rm net0123456789abcdef")) {
		t.Fatalf("want a failed run whose cleanup still ran; exit %d, calls:\n%s", code, calls)
	}
}

// With Docker (SANDPROBE_FIXTURES=1, as test/fixtures.sh sets): a locked-down box and an open one, end to end, with
// nothing left behind.
func TestDockerRun(t *testing.T) {
	if os.Getenv("SANDPROBE_FIXTURES") == "" {
		t.Skip("needs Docker and the fixture images: run test/fixtures.sh first")
	}
	bin := filepath.Join(t.TempDir(), "sandprobe")
	if b, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	for name, tc := range map[string]struct {
		opts  []string
		score int
	}{
		"locked": {[]string{"--read-only", "--tmpfs", "/tmp", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--network", "none"}, 6},
		"open":   {nil, 3},
	} {
		out := t.TempDir()
		args := append([]string{"run", "docker", "sandprobe-fixture-clean", "-as", "agent", "-y", "-o", "json", "-out", out}, "--")
		cmd := exec.Command(bin, append(args, tc.opts...)...)
		b, err := cmd.Output()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var d struct {
			Grade   struct{ Valid bool }
			Cleanup struct{ Outcome string }
		}
		if json.Unmarshal(b, &d) != nil || !d.Grade.Valid || !strings.HasPrefix(d.Cleanup.Outcome, "deleted") {
			t.Fatalf("%s: want a valid run, everything deleted: %s", name, b)
		}
		m, _ := filepath.Glob(filepath.Join(out, "*.json"))
		sc, _ := exec.Command(bin, "scorecard", m[0], "-o", "json").Output()
		var c struct{ Score int }
		json.Unmarshal(sc, &c)
		if c.Score != tc.score {
			t.Errorf("%s: want %d/6, got %d", name, tc.score, c.Score)
		}
	}
	// The user graded is the container's own after the person's options, both ways round, and an image's VOLUME leaves
	// no anonymous volume behind (PR #40 review).
	ctx := filepath.Join(t.TempDir(), "img")
	os.MkdirAll(ctx, 0o755)
	os.WriteFile(filepath.Join(ctx, "Dockerfile"), []byte("FROM sandprobe-fixture-clean\nUSER agent\nVOLUME /data\n"), 0o644)
	if b, err := exec.Command("docker", "build", "-q", "-t", "sandprobe-test-agent-volume", ctx).CombinedOutput(); err != nil {
		t.Fatalf("building the test image: %v %s", err, b)
	}
	defer exec.Command("docker", "rmi", "sandprobe-test-agent-volume").Run()
	anon := func() []string {
		b, _ := exec.Command("docker", "volume", "ls", "-q", "--filter", "label=com.docker.volume.anonymous").Output()
		return strings.Fields(string(b))
	}
	before := anon()
	for name, tc := range map[string]struct {
		image string
		opts  []string
		uid   int
	}{
		"non-root image run as root": {"sandprobe-test-agent-volume", []string{"--user", "0", "--network", "none"}, 0},
		"root image run as 1000":     {"sandprobe-fixture-clean", []string{"--user", "1000", "--network", "none"}, 1000},
	} {
		out := t.TempDir()
		b, err := exec.Command(bin, append([]string{"run", "docker", tc.image, "-y", "-o", "json", "-out", out, "--"}, tc.opts...)...).Output()
		if err != nil && len(b) == 0 {
			t.Fatalf("%s: %v", name, err)
		}
		var d struct {
			Identity struct{ UID int }
			Cleanup  struct{ Outcome string }
		}
		if json.Unmarshal(b, &d) != nil || d.Identity.UID != tc.uid || !strings.HasPrefix(d.Cleanup.Outcome, "deleted") {
			t.Errorf("%s: want uid %d graded and everything deleted, got %s", name, tc.uid, b[:min(len(b), 300)])
		}
	}
	for _, v := range anon() {
		if !slices.Contains(before, v) {
			t.Errorf("an anonymous volume was left behind: %s", v)
		}
	}
	if left, _ := exec.Command("docker", "network", "ls", "-q", "--filter", "name=sandprobe-").Output(); len(bytes.TrimSpace(left)) != 0 {
		t.Errorf("a Sandprobe network was left behind")
	}
}

// DKR-1 and DKR-4: Sandprobe's idle process is the entrypoint, with no init of Docker's ahead of it, unless the person
// names their own entrypoint (either spelling) or --init; its scratch only on a read-only root.
func TestDockerEntrypointArgs(t *testing.T) {
	for name, tc := range map[string]struct {
		opts              []string
		idle, noInit, tmp bool
	}{
		"nothing named":     {nil, true, true, false},
		"--entrypoint X":    {[]string{"--entrypoint", "/bin/cat", "-i"}, false, false, false},
		"--entrypoint=X":    {[]string{"--entrypoint=/bin/cat"}, false, false, false},
		"--init":            {[]string{"--init"}, true, false, false},
		"--init=false":      {[]string{"--init=false"}, true, false, false},
		"--read-only=true":  {[]string{"--read-only=true"}, true, true, true},
		"--read-only=false": {[]string{"--read-only=false"}, true, true, false},
	} {
		args := boxArgs("net1", "172.30.100.10", "/tmp/p", "img", tc.opts)
		ours := slices.Contains(args, dockerProbePath) && args[len(args)-1] == dockerIdle
		added := slices.Contains(args[6+len(tc.opts):], "--init=false") // after run -d, the network, the resolver and their options
		if ours != tc.idle || added != tc.noInit || slices.Contains(args, dockerScratchSpec) != tc.tmp {
			t.Errorf("%s: want idle %v, --init=false %v, scratch %v; got %q", name, tc.idle, tc.noInit, tc.tmp, args)
		}
		if n := strings.Count(strings.Join(args, " "), "--entrypoint"); !tc.idle && (args[len(args)-1] != "img" || n != 1) {
			t.Errorf("%s: the person's entrypoint runs alone, with nothing after the image: %q", name, args)
		}
	}
}

// DKR-1, DKR-4 and DKR-5: the plan says what runs, what Sandprobe adds, and that nothing is marked or reset.
func TestDockerPlanSaysWhatRuns(t *testing.T) {
	p := dockerPlan("img", "agent", nil)
	if runs := strings.Join(p.Runs, " "); !strings.Contains(runs, "idle process") || !strings.Contains(runs, "don't run") {
		t.Errorf("default: the plan must say Sandprobe's idle process runs and the image's doesn't: %q", runs)
	}
	if !strings.HasPrefix(p.Markers, "none") || !strings.HasPrefix(p.Reset, "none") {
		t.Errorf("PER-5 never runs on docker: want no markers and no reset, got %q / %q", p.Markers, p.Reset)
	}
	if strings.Contains(strings.Join(p.Creates, " "), dockerScratch) {
		t.Errorf("no read-only root: want no scratch tmpfs, got %q", p.Creates)
	}
	p = dockerPlan("img", "agent", []string{"--read-only", "--entrypoint=/bin/cat"})
	if runs := strings.Join(p.Runs, " "); !strings.Contains(runs, "your --entrypoint /bin/cat") || !strings.Contains(runs, "count it") {
		t.Errorf("the person's entrypoint: the plan must say it runs and is counted: %q", runs)
	}
	if !strings.Contains(strings.Join(p.Creates, " "), "Sandprobe's own addition: a 16 MB tmpfs at "+dockerScratch) {
		t.Errorf("read-only root: the plan must name Sandprobe's scratch as its own addition: %q", p.Creates)
	}
}

// DKR-3: the fix line runs as pasted. Through a real shell, it becomes the same command without the person's
// --entrypoint, and the CLI parses it to a plan with Sandprobe's idle process and every other option kept.
func TestDockerStopFixRunsAsPasted(t *testing.T) {
	opts := []string{"--entrypoint", "/bin/sh", "--label", "it's a test", "--read-only", "--entrypoint=/x"}
	err := dockerStopErr("before the probe ran", "your --entrypoint /x exited with code 0", "my img", "agent user", opts)
	var ce *cliError
	if !errors.As(err, &ce) || ce.Code != "provider_error" || ce.exit != exitPartial || strings.Contains(ce.Fix, "--entrypoint") ||
		ce.Message != "the container stopped before the probe ran: your --entrypoint /x exited with code 0" {
		t.Fatalf("want a named cause and a fix without the entrypoint, got %#v", err)
	}
	words, e := exec.Command("sh", "-c", "set -- "+strings.TrimPrefix(ce.Fix, "sandprobe ")+`; printf '%s\n' "$@"`).Output()
	if e != nil {
		t.Fatal(e)
	}
	args := strings.Split(strings.TrimSuffix(string(words), "\n"), "\n")
	want := []string{"run", "docker", "my img", "-as", "agent user", "-y", "--", "--label", "it's a test", "--read-only"}
	if !slices.Equal(args, want) {
		t.Fatalf("the shell reads the fix as %q, want %q", args, want)
	}
	fakeDocker(t, "")
	args[0] = "plan"
	var out, errb bytes.Buffer
	if code := run(append(args[:6:6], append([]string{"-o", "json"}, args[6:]...)...), &out, &errb); code != 0 {
		t.Fatalf("the fix didn't parse: %d %s", code, errb.String())
	}
	var p planDoc
	if json.Unmarshal(out.Bytes(), &p) != nil || !strings.Contains(strings.Join(p.Creates, " "), "--label it's a test --read-only") ||
		!strings.Contains(strings.Join(p.Runs, " "), "idle process") {
		t.Errorf("want a plan with the person's other options and Sandprobe's idle process: %s", out.String())
	}
	// Sandprobe's own idle process stopped: the fix drops the person's options, to show whether one of them stops it.
	if err := dockerStopErr("while the probe ran", "x", "img", "", []string{"--memory", "4m"}); !errors.As(err, &ce) || ce.Fix != "sandprobe run docker img -y" {
		t.Errorf("want the run without the options, got %#v", err)
	}
}

// fakeDocker puts a fake docker first on PATH. It answers as a container whose entrypoint (stop) exits at once
// ("before"), or that is killed while the probe runs ("during"), and logs every call; it returns the log's path.
func fakeDocker(t *testing.T, stop string) string {
	dir := t.TempDir()
	log, died := filepath.Join(dir, "calls.log"), filepath.Join(dir, "died")
	script := `#!/bin/sh
printf '%s\n' "$*" >> "` + log + `"
case "$*" in
  "info --format {{.Architecture}}") echo aarch64 ;;
  "image inspect"*) echo sha256:fake ;;
  "network ls -q") ;;
  "network create"*) echo net0123456789abcdef ;;
  "run -d"*/sandprobe-canary:ro*) echo canary0123456789abcdef ;;
  "run -d"*) echo box0123456789abcdef ;;
  "port "*) echo 127.0.0.1:1 ;;
  "volume ls -q") ;;
  "inspect --type container -f {\"mounts\""*) echo '{"mounts":[],"binds":null,"declared":[],"volumes_from":null}' ;;
  "inspect --type container --format {{.State.Running}}"*)
    case "` + stop + `" in
      before) echo "false 0 false" ;;
      during) if [ -f "` + died + `" ]; then echo "false 137 false"; else echo "true 0 false"; fi ;;
    esac ;;
  "inspect --type container --format {{.Config.User}}"*) echo ;;
  "inspect --type container --format {{json .Path}}"*) echo '"/opt/sandprobe/sandprobe-probe" ["-idle"] "" false' ;;
  "exec canary"*) echo '{"ok":true}' ;;
  "exec -i -u"*-survey) echo '{"schema":"sandprobe.survey/1","proxy":null,"kube_api":"","vsock":false,"roots":[]}' ;;
  "exec -i -u"*) touch "` + died + `"; exit 137 ;;
  "inspect --type container"*|"inspect --type container -f {{.Id}}"*) echo "Error: No such container" >&2; exit 1 ;;
  "network inspect"*) echo "Error: network not found" >&2; exit 1 ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return log
}

// DKR-3: a container that stops before or while the probe runs ends the run with what stopped and how, never "see the
// message" or a bare invalid run, and its cleanup still runs.
func TestDockerStopNamesTheCause(t *testing.T) {
	for name, tc := range map[string]struct {
		stop, message, fix string
		opts               []string
	}{
		"their entrypoint exits at once": {"before", "the container stopped before the probe ran: your --entrypoint /bin/cat exited with code 0",
			"sandprobe run docker img -as agent -y -- --read-only", []string{"--entrypoint", "/bin/cat", "--read-only"}},
		"killed while the probe ran": {"during", "the container stopped while the probe ran: Sandprobe's idle process, the container's entrypoint, was killed by signal 9 (exit code 137)",
			"sandprobe run docker img -as agent -y", nil},
	} {
		t.Run(name, func(t *testing.T) {
			log := fakeDocker(t, tc.stop)
			var out, errb bytes.Buffer
			code := run(append([]string{"run", "docker", "img", "-as", "agent", "-y", "-o", "json", "-out", t.TempDir(), "--"}, tc.opts...), &out, &errb)
			var e struct{ Error, Message, Fix string }
			json.Unmarshal(out.Bytes(), &e)
			if code != exitPartial || e.Message != tc.message || e.Fix != tc.fix {
				t.Fatalf("want exit 5, %q and %q; got %d %+v %s", tc.message, tc.fix, code, e, errb.String())
			}
			calls, _ := os.ReadFile(log)
			if !bytes.Contains(calls, []byte("rm -f box0123456789abcdef")) || !bytes.Contains(calls, []byte("network rm net0123456789abcdef")) {
				t.Errorf("the cleanup must still run:\n%s", calls)
			}
		})
	}
}

// With Docker (SANDPROBE_FIXTURES=1): DKR-1 to DKR-4 end to end, on an image whose own entrypoint exits at once, as
// most agent images' does without a task or a terminal, and whose user is the agent's.
func TestDockerEntrypointRuns(t *testing.T) {
	if os.Getenv("SANDPROBE_FIXTURES") == "" {
		t.Skip("needs Docker and the fixture images: run test/fixtures.sh first")
	}
	bin := filepath.Join(t.TempDir(), "sandprobe")
	if b, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	ctx := filepath.Join(t.TempDir(), "img")
	os.MkdirAll(ctx, 0o755)
	// exit-mid-run.sh exits 3 once the probe's main run is up: its private scratch directory, which lives from the
	// run's start to its end, has appeared in /tmp. Shell builtins only, so no run is too short to be seen.
	os.WriteFile(filepath.Join(ctx, "exit-mid-run.sh"), []byte("#!/bin/sh\nwhile :; do\n  for d in /tmp/sandprobe-*; do\n"+
		"    [ -e \"$d\" ] && exit 3\n  done\n  sleep 0.01\ndone\n"), 0o755)
	os.WriteFile(filepath.Join(ctx, "Dockerfile"), []byte("FROM sandprobe-fixture-clean\nCOPY exit-mid-run.sh /exit-mid-run.sh\n"+
		"USER agent\nENTRYPOINT [\"true\"]\n"), 0o644)
	if b, err := exec.Command("docker", "build", "-q", "-t", "sandprobe-test-exits", ctx).CombinedOutput(); err != nil {
		t.Fatalf("building the test image: %v %s", err, b)
	}
	defer exec.Command("docker", "rmi", "sandprobe-test-exits").Run()
	type outcome struct {
		Message  string
		Grade    struct{ Valid bool }
		Checks   []struct{ ID, Result, Evidence string }
		Cleanup  struct{ Outcome, Residual string }
		Manifest struct{ Skipped map[string]string }
	}
	runIt := func(opts ...string) (outcome, int) {
		cmd := exec.Command(bin, append([]string{"run", "docker", "sandprobe-test-exits", "-as", "agent", "-y", "-o", "json", "-out", t.TempDir(), "--"}, opts...)...)
		b, _ := cmd.Output()
		var o outcome
		if err := json.Unmarshal(b, &o); err != nil {
			t.Fatalf("%q: %v: %s", opts, err, b)
		}
		return o, cmd.ProcessState.ExitCode()
	}
	result := func(o outcome, id string) (string, string) {
		for _, c := range o.Checks {
			if c.ID == id {
				return c.Result, c.Evidence
			}
		}
		return "", ""
	}
	// The image's entrypoint never runs; Sandprobe's idle process, the agent's own uid, isn't counted (DKR-1, DKR-2).
	// On a read-only root with no writable /tmp, the probe has Sandprobe's own scratch, and PER-5 is skipped (DKR-4, DKR-5).
	for _, opts := range [][]string{nil, {"--read-only", "--network", "none"}} {
		o, _ := runIt(opts...)
		r2, _ := result(o, "SEC-2")
		r5, _ := result(o, "SEC-5")
		if !o.Grade.Valid || r2 != "scoped_out" || r5 != "scoped_out" || !strings.HasPrefix(o.Cleanup.Outcome, "deleted") ||
			!strings.Contains(o.Manifest.Skipped["PER-5"], "no root this run may mark") || !strings.Contains(o.Cleanup.Residual, "DKR-2") ||
			strings.Contains(o.Cleanup.Residual, "DKR-4") != (opts != nil) {
			t.Errorf("%q: want a valid run, SEC-2 and SEC-5 scoped out, PER-5 skipped, everything deleted: %+v", opts, o)
		}
	}
	// The spoof: the person's own --entrypoint is Sandprobe's probe path, kept alive on stdin as the agent's uid. It
	// is theirs, so it is counted (DKR-2). So is everything with --init, whose PID 1 is Docker's init.
	for _, opts := range [][]string{{"-i", "--entrypoint", dockerProbePath}, {"--init"}} {
		o, _ := runIt(opts...)
		if r, ev := result(o, "SEC-2"); r != "finding" || !strings.Contains(ev, "/proc/1/environ") {
			t.Errorf("%q: want PID 1 counted, got %s %q", opts, r, ev)
		}
	}
	// The person's entrypoint exits at once, or once the probe's main run is up (DKR-3).
	for ep, want := range map[string]string{
		"/bin/true":        "the container stopped before the probe ran: your --entrypoint /bin/true exited with code 0",
		"/exit-mid-run.sh": "the container stopped while the probe ran: your --entrypoint /exit-mid-run.sh exited with code 3",
	} {
		o, code := runIt("--entrypoint", ep)
		if code != exitPartial || o.Message != want {
			t.Errorf("%s: want exit 5 naming %q, got %d %q", ep, want, code, o.Message)
		}
	}
	if left, _ := exec.Command("docker", "network", "ls", "-q", "--filter", "name=sandprobe-").Output(); len(bytes.TrimSpace(left)) != 0 {
		t.Errorf("a Sandprobe network was left behind")
	}
}
