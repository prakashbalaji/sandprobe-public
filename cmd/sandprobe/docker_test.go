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
	"time"
)

// PRV-14: the person's options pass through unchanged; Sandprobe's network and resolver only when they name none.
func TestDockerBoxArgs(t *testing.T) {
	own := boxArgs("net1", "172.30.100.10", "/tmp/p", "img", []string{"--read-only"})
	if !slices.Equal(own, []string{"run", "-d", "--network", "net1", "--dns", "172.30.100.10", "--read-only",
		"-v", "/tmp/p:" + dockerProbePath + ":ro", "img"}) {
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
