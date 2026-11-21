package host

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeProbe stands in for the shipped probe, run by a real local sh: -whoami answers with this user's uid, or with
// whoUID when the test sets one; anything else prints its arguments, its stdin and SEC-1's twin.
func fakeProbe(whoUID string) []byte {
	me := strconv.Itoa(os.Getuid())
	if whoUID == "" {
		whoUID = me
	}
	return []byte(`#!/bin/sh
if [ "$1" = -whoami ]; then
  printf '{"schema":"sandprobe.whoami/1","uids":[` + me + `,` + me + `,` + me + `,` + me + `],"name":"%s","name_uid":` + whoUID + `,"temp_dir":"/tmp"}\n' "$2"
  exit 0
fi
if [ "$1" = -sleep ] || [ "$3" = -sleep ]; then sleep 30; fi
printf 'ARGS:%s\n' "$*"
printf 'IN:%s\n' "$(cat)"
printf 'TWIN:%s\n' "$SANDPROBE_TWIN"
`)
}

func execBox(t *testing.T, command []string, probe []byte) *ExecBox {
	t.Helper()
	b, err := NewExecBox(command, probe, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// PRV-15: the preflight binds the user, every later run carries the binding, banners outside the markers are ignored,
// and the scratch path is gone after each invocation.
func TestExecBoxRoundTrip(t *testing.T) {
	b := execBox(t, []string{"sh", "-c", "echo 'Welcome to the box'; exec sh"}, fakeProbe(""))
	ctx := context.Background()
	if _, err := b.Probe(ctx, []string{"-survey"}, nil); err == nil {
		t.Fatal("a probe ran before the identity preflight")
	}
	w, err := b.Preflight(ctx, "")
	if err != nil || w.UIDs[1] != os.Getuid() {
		t.Fatalf("preflight: %+v %v", w, err)
	}
	out, err := b.Probe(ctx, []string{"-survey"}, []byte(`{"hello":"box"}`))
	if err != nil {
		t.Fatal(err)
	}
	want := "ARGS:-expect-uid " + strconv.Itoa(os.Getuid()) + " -survey\nIN:{\"hello\":\"box\"}\nTWIN:1\n"
	if string(out) != want {
		t.Fatalf("got %q, want %q", out, want)
	}
	if _, err := os.Stat(b.Scratch); !os.IsNotExist(err) {
		t.Fatalf("the scratch %s is still there: %v", b.Scratch, err)
	}
	if err := b.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
}

// PRV-15: when the requested user isn't who the command runs as, nothing else runs.
func TestExecBoxPreflightRefusesAnotherUser(t *testing.T) {
	b := execBox(t, []string{"sh"}, fakeProbe(strconv.Itoa(os.Getuid()+1)))
	if _, err := b.Preflight(context.Background(), "agent"); err == nil || !strings.Contains(err.Error(), "nothing else runs") {
		t.Fatalf("want a refusal, got %v", err)
	}
	if _, err := b.Probe(context.Background(), []string{"-survey"}, nil); err == nil {
		t.Fatal("a probe ran after a refused preflight")
	}
}

// A scratch path that already exists isn't ours: nothing runs, and it's left alone.
func TestExecBoxScratchAlreadyThere(t *testing.T) {
	b := execBox(t, []string{"sh"}, fakeProbe(""))
	if err := os.Mkdir(b.Scratch, 0o700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(b.Scratch, "theirs"), []byte("x"), 0o600)
	if _, err := b.Preflight(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("want a refusal, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(b.Scratch, "theirs")); err != nil {
		t.Fatal("a path that wasn't ours was removed")
	}
}

// PRV-15: an invocation killed past its limit skips its own trap; the separate removal invocation still clears the
// scratch path, and if even that can't run, Cleanup names the path and the command that removes it.
func TestExecBoxKilledInvocation(t *testing.T) {
	defer func(d time.Duration) { ExecCommandLimit = d }(ExecCommandLimit)
	ExecCommandLimit = 2 * time.Second
	b := execBox(t, []string{"sh"}, fakeProbe(""))
	ctx := context.Background()
	if _, err := b.Preflight(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Probe(ctx, []string{"-sleep"}, nil); err == nil {
		t.Fatal("a killed invocation succeeded")
	}
	if _, err := os.Stat(b.Scratch); !os.IsNotExist(err) {
		t.Fatalf("the removal invocation left %s", b.Scratch)
	}
	if err := b.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}

	// The transport works once, then never again: the scratch can't be confirmed gone.
	flag := filepath.Join(t.TempDir(), "used")
	once := execBox(t, []string{"sh", "-c", "if [ -e '" + flag + "' ]; then exit 1; fi; : > '" + flag + "'; exec sh"}, fakeProbe(""))
	once.Preflight(ctx, "")
	err := once.Cleanup(ctx)
	if err == nil || !strings.Contains(err.Error(), once.Scratch) || !strings.Contains(err.Error(), ".sp-owner") {
		t.Fatalf("want the path and its removal command, got %v", err)
	}
	if _, err := once.Probe(ctx, []string{"-survey"}, nil); err == nil {
		t.Fatal("a probe ran with an earlier scratch unconfirmed")
	}
}

func TestNewExecBoxChecks(t *testing.T) {
	for _, tc := range []struct {
		cmd []string
		dir string
	}{
		{nil, ""}, {[]string{""}, ""}, {[]string{"no-such-command-sandprobe"}, ""},
		{[]string{"sh"}, "relative"}, {[]string{"sh"}, "/tmp/../etc"}, {[]string{"sh"}, "/tmp/it's"}, {[]string{"sh"}, "/tmp/$HOME"},
		{[]string{"sh"}, "/tmp/"},
	} {
		if _, err := NewExecBox(tc.cmd, nil, tc.dir); err == nil {
			t.Errorf("%q in %q accepted", tc.cmd, tc.dir)
		}
	}
	b, err := NewExecBox([]string{"sh"}, nil, "")
	if err != nil || !scratchPath.MatchString(b.Scratch) || !strings.HasPrefix(b.Scratch, "/tmp/sandprobe-") {
		t.Fatalf("%v %v", b, err)
	}
	if _, err := b.invoke(context.Background(), []string{"-survey; rm -rf /"}, nil); err == nil {
		t.Fatal("an argument with shell syntax was sent")
	}
}

func TestUnframe(t *testing.T) {
	tok := "0123456789abcdef01234567"
	for _, tc := range []struct {
		in     string
		out    string
		status int
		ok     bool
	}{
		{"banner\nSP-START-" + tok + "\n{\"a\":1}\n\nSP-END-" + tok + " 0\nbye\n", "{\"a\":1}\n", 0, true},
		{"SP-START-" + tok + " 97\n", "", 97, true},
		{"SP-START-" + tok + "\npartial", "", 0, false},
		{"SP-START-other\nx\nSP-END-other 0\n", "", 0, false},
		{"", "", 0, false},
	} {
		out, status, ok := unframe([]byte(tc.in), tok)
		if string(out) != tc.out || status != tc.status || ok != tc.ok {
			t.Errorf("%q: %q %d %v", tc.in, out, status, ok)
		}
	}
}

// A command that runs the script but then fails doesn't count as a probe run, even with its output framed.
func TestExecBoxFailedCommandCountsForNothing(t *testing.T) {
	b := execBox(t, []string{"sh", "-c", "sh; exit 7"}, fakeProbe(""))
	if _, err := b.Preflight(context.Background(), ""); err == nil {
		t.Fatal("a preflight through a failing command passed")
	}
}

// "Can't tell" is never "gone": a scratch whose parent the shell can't search isn't confirmed removed.
func TestExecBoxUnsearchableParentIsNotGone(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root searches any directory")
	}
	parent := t.TempDir()
	b, err := NewExecBox([]string{"sh"}, nil, parent)
	if err != nil {
		t.Fatal(err)
	}
	// The stand-in probe answers the preflight, then locks the scratch's parent, so neither the trap nor the removal
	// invocation can remove or even see the scratch.
	b.Binary = []byte("#!/bin/sh\nme=$(id -u)\nprintf '{\"schema\":\"sandprobe.whoami/1\",\"uids\":[%s,%s,%s,%s],\"temp_dir\":\"/tmp\"}\\n' $me $me $me $me\nchmod 000 '" + parent + "'\n")
	defer os.Chmod(parent, 0o755)
	b.Preflight(context.Background(), "")
	err = b.Cleanup(context.Background())
	if err == nil || !strings.Contains(err.Error(), b.Scratch) {
		t.Fatalf("an unsearchable scratch was called gone: %v", err)
	}
}

// A removal invocation that prints "gone" through a command that then fails confirms nothing.
func TestExecBoxGoneNeedsASucceedingCommand(t *testing.T) {
	b := execBox(t, []string{"sh", "-c", "sh; exit 3"}, fakeProbe(""))
	b.Preflight(context.Background(), "")
	if err := b.Cleanup(context.Background()); err == nil {
		t.Fatal("a failing command's removal was taken as confirmed")
	}
}

// A pre-existing scratch path whose "already exists" answer is lost on the way back is still never removed: only a
// directory carrying this box's mark is Sandprobe's.
func TestExecBoxLostMarkerNeverRemovesWhatIsntOurs(t *testing.T) {
	b := execBox(t, []string{"sh", "-c", "sh | grep -v SP-START; true"}, fakeProbe(""))
	if err := os.Mkdir(b.Scratch, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(b.Scratch, "theirs")
	os.WriteFile(sentinel, []byte("x"), 0o600)
	if _, err := b.Preflight(context.Background(), ""); err == nil {
		t.Fatal("a preflight with its marker lost passed")
	}
	err := b.Cleanup(context.Background())
	if _, serr := os.Stat(sentinel); serr != nil {
		t.Fatal("a path that wasn't ours was removed")
	}
	if err == nil || !strings.Contains(err.Error(), "left alone") || strings.Contains(err.Error(), "rm -rf") {
		t.Fatalf("want it reported and left alone, with no removal command: %v", err)
	}
}

// A path the box swaps in for the scratch while the probe runs isn't Sandprobe's: the wrapper's own exit trap leaves it,
// and the suggested manual removal checks the mark too.
func TestExecBoxTrapLeavesASwappedPath(t *testing.T) {
	probe := []byte("#!/bin/sh\n" + `if [ "$1" = -whoami ]; then me=$(id -u); printf '{"schema":"sandprobe.whoami/1","uids":[%s,%s,%s,%s],"temp_dir":"/tmp"}\n' $me $me $me $me; exit 0; fi
d=$(dirname "$0"); rm -rf "$d"; mkdir "$d"; echo x > "$d/theirs"; echo '{}'` + "\n")
	b := execBox(t, []string{"sh"}, probe)
	ctx := context.Background()
	if _, err := b.Preflight(ctx, ""); err != nil {
		t.Fatal(err)
	}
	b.Probe(ctx, []string{"-survey"}, nil)
	if _, err := os.Stat(filepath.Join(b.Scratch, "theirs")); err != nil {
		t.Fatal("the exit trap removed a path the box swapped in")
	}
	err := b.Cleanup(ctx)
	if err == nil || !strings.Contains(err.Error(), "left alone") {
		t.Fatalf("want it reported and left alone: %v", err)
	}
	if rc := b.RemovalCommand(); !strings.Contains(rc, ".sp-owner") || !strings.Contains(rc, b.owner) {
		t.Fatalf("the manual removal doesn't check the mark: %s", rc)
	}
	os.RemoveAll(b.Scratch)
}

func TestExecBoxArch(t *testing.T) {
	for in, want := range map[string]string{"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"} {
		b := execBox(t, []string{"sh", "-c", "uname() { echo " + in + "; }; eval \"$(cat)\""}, nil)
		if got, err := b.Arch(context.Background()); err != nil || got != want {
			t.Errorf("%s: %q %v", in, got, err)
		}
	}
	b := execBox(t, []string{"sh", "-c", "uname() { echo riscv64; }; eval \"$(cat)\""}, nil)
	if _, err := b.Arch(context.Background()); err == nil {
		t.Error("an unsupported architecture was accepted")
	}
	failing := execBox(t, []string{"sh", "-c", "uname() { echo x86_64; }; eval \"$(cat)\"; exit 5"}, nil)
	if _, err := failing.Arch(context.Background()); err == nil {
		t.Error("an architecture through a failing command was accepted")
	}
	for id := range ExecExclusions() {
		if !excludable[id] {
			t.Errorf("%s isn't a GRD-3 exclusion", id)
		}
	}
}
