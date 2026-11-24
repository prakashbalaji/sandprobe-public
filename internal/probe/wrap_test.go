//go:build linux

package probe

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"sandprobe/internal/catalog"
	"sandprobe/internal/obs"
)

const (
	testTok   = "0123456789abcdef01234567"
	testOwner = "89abcdef0123456789abcdef"
)

// wrapTestHooks lets the test binary play LNC's processes when a test re-executes it: the wrapper (-wrap), the run it
// starts (-expect-uid), and a pinning child and its parent. TestMain calls it before any test runs.
func wrapTestHooks() {
	if len(os.Args) < 2 {
		return
	}
	switch {
	case os.Args[1] == "-wrap" && os.Getenv("SANDPROBE_TEST_WRAP") == "1":
		exe := "/proc/self/exe"
		if x := os.Getenv("SANDPROBE_TEST_WRAP_EXE"); x != "" {
			exe = x
		}
		os.Exit(wrapFrom(exe, os.Args[2], os.Args[3:]))
	case os.Args[1] == "-expect-uid" && os.Getenv("SANDPROBE_TEST_RUN") != "":
		os.Exit(fakeRun(os.Getenv("SANDPROBE_TEST_RUN")))
	case os.Args[1] == "-pin" && os.Getenv("SANDPROBE_TEST_PIN") == "1":
		p := pinWrapper()
		os.Stdout.WriteString("PIN " + strconv.FormatBool(p != nil) + " " + strconv.Itoa(os.Getpid()) + "\n")
		bufio.NewReader(os.Stdin).ReadString('\n') // the test changes the parent, then says go
		os.Stdout.WriteString("HOLDS " + strconv.FormatBool(p != nil && p.holds()) + "\n")
		os.Exit(0)
	case os.Args[1] == "-pin-parent" && os.Getenv("SANDPROBE_TEST_PIN") == "1":
		usr1 := make(chan os.Signal, 1)
		signal.Notify(usr1, syscall.SIGUSR1)
		child := exec.Command(os.Args[2], "-pin")
		child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
		if child.Start() != nil {
			os.Exit(3)
		}
		<-usr1 // exec another file, keeping this PID
		syscall.Exec("/bin/sleep", []string{"sleep", "60"}, os.Environ())
		os.Exit(4)
	}
}

// fakeRun is the run a test wrapper starts.
func fakeRun(mode string) int {
	dir := os.Getenv("SANDPROBE_TEST_DIR")
	switch mode {
	case "ok":
		in, _ := io.ReadAll(os.Stdin)
		os.Stdout.WriteString("RUN-IN:" + string(in))
		return 0
	case "exit3":
		return 3
	case "sleep":
		os.Stdout.WriteString("READY " + strconv.Itoa(os.Getpid()) + "\n")
		time.Sleep(60 * time.Second)
		return 0
	case "environ":
		b, _ := os.ReadFile("/proc/self/environ")
		os.WriteFile(filepath.Join(dir, "run.environ"), b, 0o600)
		os.Stdout.WriteString("READY " + strconv.Itoa(os.Getpid()) + "\n")
		time.Sleep(60 * time.Second)
		return 0
	case "secproc":
		if os.Getenv("SANDPROBE_TEST_KILL_PARENT") == "1" { // LNC-3: the wrapper dies between the pin and the check
			victim := 0
			afterSweep = func() {
				if victim != 0 {
					return
				}
				victim = os.Getppid()
				syscall.Kill(victim, syscall.SIGKILL)
				for i := 0; i < 200 && os.Getppid() == victim; i++ {
					time.Sleep(10 * time.Millisecond)
				}
			}
		}
		tw, err := makeTwins()
		if err != nil {
			return 5
		}
		defer tw.close()
		_, discover := catalog.Plan(catalog.IDs())
		e := &env{in: Input{Discover: discover}, root: os.Geteuid() == 0, home: os.TempDir(), tw: tw}
		out := map[string]any{"ppid": os.Getppid()}
		for _, c := range [][2]string{{"SEC-2", "environ"}, {"SEC-5", "mem"}} { // the probe's order
			ck, _ := catalog.Get(c[0])
			out[c[0]] = secProc(e, ck, c[1])
		}
		out["ppid"] = os.Getppid() // after a killed wrapper, the new parent
		b, _ := json.Marshal(out)
		os.WriteFile(filepath.Join(dir, "obs.json"), b, 0o600)
		return 0
	}
	return 9
}

// scratchDir is a scratch the wrapper may remove: a real directory carrying the owner's mark.
func scratchDir(t *testing.T, mark string) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "sandprobe-"+testTok)
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, ".sp-owner"), []byte(mark+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return d
}

func uidArg() string { return strconv.Itoa(os.Getuid()) }

func wrapCmd(scratch, mode string, stdin string, extra ...string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], "-wrap", scratch, "-expect-uid", uidArg())
	cmd.Env = append(os.Environ(), append([]string{"SANDPROBE_TEST_WRAP=1", "SANDPROBE_TEST_RUN=" + mode}, extra...)...)
	cmd.Stdin = strings.NewReader(stdin)
	return cmd
}

func exists(p string) bool { _, err := os.Lstat(p); return err == nil }

// LNC-2: the wrapper frames the run, passes its status and TERM, INT and HUP on, and removes only an owned scratch.
func TestWrapFraming(t *testing.T) {
	header := testTok + " " + testOwner + "\n"
	for _, tc := range []struct {
		name, mode, stdin, exe string
		mark                   string
		status                 int
		gone                   bool
	}{
		{"success", "ok", header + `{"in":1}`, "", testOwner, 0, true},
		{"run exits 3", "exit3", header, "", testOwner, 3, true},
		{"not our mark", "ok", header, "", "ffffffffffffffffffffffff", 0, false},
		{"run can't start", "ok", header, "/nonexistent/sandprobe-probe", testOwner, WrapFailed, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := scratchDir(t, tc.mark)
			var extra []string
			if tc.exe != "" {
				extra = append(extra, "SANDPROBE_TEST_WRAP_EXE="+tc.exe)
			}
			out, err := wrapCmd(s, tc.mode, tc.stdin, extra...).Output()
			if err != nil {
				t.Fatalf("the wrapper itself failed: %v", err)
			}
			want := "SP-START-" + testTok + "\n"
			if tc.mode == "ok" && tc.exe == "" {
				want += "RUN-IN:" + strings.TrimPrefix(tc.stdin, header)
			}
			want += "\nSP-END-" + testTok + " " + strconv.Itoa(tc.status) + "\n"
			if string(out) != want {
				t.Errorf("got %q, want %q", out, want)
			}
			if exists(s) == tc.gone {
				t.Errorf("scratch gone %v, want %v", !exists(s), tc.gone)
			}
		})
	}

	// A link at the scratch path, to a directory carrying the right mark, is never followed or removed.
	real := scratchDir(t, testOwner)
	link := filepath.Join(t.TempDir(), "sandprobe-"+testTok)
	os.Symlink(real, link)
	if _, err := wrapCmd(link, "ok", header).Output(); err != nil || !exists(link) || !exists(real) {
		t.Errorf("a linked scratch was removed: %v", err)
	}

	// A short or malformed first line: nothing printed, nothing removed, a nonzero exit.
	for _, bad := range []string{"", testTok, testTok + " " + testOwner, strings.ToUpper(testTok) + " " + testOwner + "\n",
		testTok + "-" + testOwner + "\n", testTok + " " + testOwner + "x"} {
		s := scratchDir(t, testOwner)
		out, err := wrapCmd(s, "ok", bad).Output()
		if err == nil || len(out) != 0 || !exists(s) {
			t.Errorf("header %q: out %q, err %v, scratch kept %v", bad, out, err, exists(s))
		}
	}

	// TERM, INT and HUP sent to the wrapper reach the run; the wrapper still cleans up and frames its status.
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP} {
		s := scratchDir(t, testOwner)
		cmd := wrapCmd(s, "sleep", header)
		stdout, _ := cmd.StdoutPipe()
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		r := bufio.NewReader(stdout)
		r.ReadString('\n') // start marker
		if line, _ := r.ReadString('\n'); !strings.HasPrefix(line, "READY ") {
			t.Fatalf("no run: %q", line)
		}
		cmd.Process.Signal(sig)
		rest, _ := io.ReadAll(r)
		cmd.Wait()
		if want := "\nSP-END-" + testTok + " " + strconv.Itoa(128+int(sig)) + "\n"; string(rest) != want || exists(s) {
			t.Errorf("%v: got %q, scratch kept %v", sig, rest, exists(s))
		}
	}
}

// LNC-2: SIGKILL can't be caught: no end marker, and the scratch is left for PRV-15's confirm-gone invocation.
func TestWrapKilled(t *testing.T) {
	s := scratchDir(t, testOwner)
	cmd := wrapCmd(s, "sleep", testTok+" "+testOwner+"\n")
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(stdout)
	r.ReadString('\n')
	line, _ := r.ReadString('\n')
	run, _ := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "READY ")))
	cmd.Process.Kill()
	cmd.Wait()
	if run > 0 {
		syscall.Kill(run, syscall.SIGKILL) // the orphaned run holds the pipe open
	}
	rest, _ := io.ReadAll(r)
	if bytes.Contains(rest, []byte("SP-END-")) || !exists(s) {
		t.Errorf("after SIGKILL: %q, scratch kept %v", rest, exists(s))
	}
}

func readEnviron(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) == 0 {
		return []string{}
	}
	return strings.Split(string(bytes.TrimSuffix(b, []byte{0})), "\x00")
}

// waitReady starts cmd and returns once its run says READY.
func waitReady(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(stdout)
	for {
		line, err := r.ReadString('\n')
		if strings.HasPrefix(line, "READY ") {
			go io.Copy(io.Discard, r)
			return
		}
		if err != nil {
			t.Fatalf("the run never started: %v", err)
		}
	}
}

// LNC-4: the wrapper is what the shell's exec left, and the run gets its environment exactly, plus at most
// SANDPROBE_TWIN. The test, not the probe, reads both environments; every value is fake.
func TestWrapperHoldsOnlyTheRunsEnvironment(t *testing.T) {
	header := testTok + " " + testOwner + "\n"
	dash := false
	if p, err := filepath.EvalSymlinks("/bin/sh"); err == nil {
		dash = strings.HasSuffix(p, "dash")
	}

	// Through sh: a name dash doesn't pass on, and a value the shell changed before its exec.
	dir := t.TempDir()
	cmd := exec.Command("/bin/sh", "-c", `FOO_TOKEN=sandprobe-fake-b; export FOO_TOKEN; exec "$0" -wrap "$1" -expect-uid "$2"`,
		os.Args[0], scratchDir(t, testOwner), uidArg())
	cmd.Env = append(os.Environ(), "MY-KEY=sandprobe-fake", "a.b=sandprobe-fake", "FOO_TOKEN=sandprobe-fake-a",
		"SANDPROBE_TEST_WRAP=1", "SANDPROBE_TEST_RUN=environ", "SANDPROBE_TEST_DIR="+dir)
	cmd.Stdin = strings.NewReader(header)
	waitReady(t, cmd)
	wrapper := readEnviron(t, "/proc/"+strconv.Itoa(cmd.Process.Pid)+"/environ") // the shell's PID, now the wrapper
	run := readEnviron(t, filepath.Join(dir, "run.environ"))
	cmd.Process.Signal(syscall.SIGTERM)
	cmd.Wait()
	want := slices.Clone(wrapper) // SANDPROBE_TWIN=1 only when the wrapper holds no such name (an earlier test may set it)
	if !slices.ContainsFunc(wrapper, func(s string) bool { return strings.HasPrefix(s, "SANDPROBE_TWIN=") }) {
		want = append(want, "SANDPROBE_TWIN=1")
	}
	if !slices.Equal(run, want) {
		t.Errorf("the run's environment isn't the wrapper's plus SANDPROBE_TWIN:\nwrapper %q\nrun     %q", wrapper, run)
	}
	for _, env := range [][]string{wrapper, run} {
		if !slices.Contains(env, "FOO_TOKEN=sandprobe-fake-b") || slices.Contains(env, "FOO_TOKEN=sandprobe-fake-a") {
			t.Errorf("the changed value isn't the only one held: %q", env)
		}
		if dash && (slices.ContainsFunc(env, func(s string) bool { return strings.HasPrefix(s, "MY-KEY=") || strings.HasPrefix(s, "a.b=") })) {
			t.Errorf("dash dropped MY-KEY and a.b, yet the wrapper holds one: %q", env)
		}
	}

	// Started directly: duplicates, an entry without "=" and an empty entry pass through in order; an existing
	// SANDPROBE_TWIN is never rewritten or added again.
	for _, base := range [][]string{
		{"DUP=1", "DUP=2", "NOEQ", "", "PATH=/usr/bin:/bin"},
		{"SANDPROBE_TWIN=0", "DUP=1", "DUP=1"},
	} {
		dir := t.TempDir()
		env := append([]string{"SANDPROBE_TEST_WRAP=1", "SANDPROBE_TEST_RUN=environ", "SANDPROBE_TEST_DIR=" + dir}, base...)
		inR, inW, _ := os.Pipe()
		outR, outW, _ := os.Pipe()
		p, err := os.StartProcess(os.Args[0], []string{os.Args[0], "-wrap", scratchDir(t, testOwner), "-expect-uid", uidArg()},
			&os.ProcAttr{Env: env, Files: []*os.File{inR, outW, os.Stderr}}) // no exec.Cmd: it would dedupe
		inR.Close()
		outW.Close()
		if err != nil {
			t.Fatal(err)
		}
		inW.WriteString(header)
		r := bufio.NewReader(outR)
		for line, err := r.ReadString('\n'); !strings.HasPrefix(line, "READY "); line, err = r.ReadString('\n') {
			if err != nil {
				t.Fatal("the run never started")
			}
		}
		want := slices.Clone(env)
		if !slices.Contains(base, "SANDPROBE_TWIN=0") {
			want = append(want, "SANDPROBE_TWIN=1")
		}
		if got := readEnviron(t, filepath.Join(dir, "run.environ")); !slices.Equal(got, want) {
			t.Errorf("run environment %q, want %q", got, want)
		}
		p.Signal(syscall.SIGTERM)
		p.Wait()
		inW.Close()
		outR.Close()
	}
}

// pinChild starts a pinning child under parent (args), and returns its PIN line's verdict and PID, its stdin and
// its reader.
func pinChild(t *testing.T, args ...string) (*exec.Cmd, bool, int, io.WriteCloser, *bufio.Reader) {
	t.Helper()
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = append(os.Environ(), "SANDPROBE_TEST_PIN=1")
	in, _ := cmd.StdinPipe()
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { in.Close(); cmd.Process.Kill(); cmd.Wait() })
	r := bufio.NewReader(out)
	line, _ := r.ReadString('\n')
	f := strings.Fields(line)
	if len(f) != 3 || f[0] != "PIN" {
		t.Fatalf("no pin line: %q", line)
	}
	pid, _ := strconv.Atoi(f[2])
	return cmd, f[1] == "true", pid, in, r
}

func holdsAfter(t *testing.T, in io.WriteCloser, r *bufio.Reader) bool {
	t.Helper()
	in.Write([]byte("go\n"))
	line, _ := r.ReadString('\n')
	return strings.TrimSpace(line) == "HOLDS true"
}

// LNC-3: only a parent running the probe's own file is pinned, and a pin fails once that parent dies, execs another
// file, or is no longer the parent.
func TestParentPin(t *testing.T) {
	self := os.Args[0]
	// A parent running the same file: pinned, and the pin holds.
	_, pinned, _, in, r := pinChild(t, self, "-pin-parent", self)
	if !pinned || !holdsAfter(t, in, r) {
		t.Error("a parent running the probe's own file wasn't pinned, or its pin didn't hold")
	}
	// The parent dies: the pin no longer holds.
	parent, pinned, child, in, r := pinChild(t, self, "-pin-parent", self)
	parent.Process.Kill()
	parent.Wait()
	waitParentChange(t, child, parent.Process.Pid)
	if !pinned || holdsAfter(t, in, r) {
		t.Error("a pin held after its parent died")
	}
	// The parent execs another file: same PID, another file, so the pin fails.
	parent, pinned, _, in, r = pinChild(t, self, "-pin-parent", self)
	parent.Process.Signal(syscall.SIGUSR1)
	waitExe(t, parent.Process.Pid, "/bin/sleep")
	if !pinned || holdsAfter(t, in, r) {
		t.Error("a pin held after its parent exec'd another file")
	}
	// A parent running another file, and a copy of the probe at another path: never pinned.
	if _, pinned, _, _, _ := pinChild(t, "/bin/sh", "-c", `"$0" -pin; :`, self); pinned {
		t.Error("a sh parent was pinned")
	}
	cp := filepath.Join(t.TempDir(), "copy")
	b, _ := os.ReadFile(self)
	os.WriteFile(cp, b, 0o700)
	if _, pinned, _, _, _ := pinChild(t, cp, "-pin-parent", self); pinned {
		t.Error("a parent running a copy of the probe at another path was pinned")
	}
	// No parent in the box, this process itself, and a PID that is nobody's: never pinned.
	for _, pid := range []int{0, os.Getpid(), 1 << 22} {
		if pinParent(pid) != nil {
			t.Errorf("PID %d, not this probe's parent, was pinned", pid)
		}
	}
}

func waitParentChange(t *testing.T, pid, from int) {
	t.Helper()
	for i := 0; i < 300; i++ {
		b, _ := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
		if f := strings.Fields(string(b[bytes.LastIndexByte(b, ')')+1:])); len(f) > 1 && f[1] != strconv.Itoa(from) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the child was never reparented")
}

func waitExe(t *testing.T, pid int, want string) {
	t.Helper()
	for i := 0; i < 300; i++ {
		if got, _ := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe"); got == want || strings.HasSuffix(got, "/sleep") {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the parent never exec'd")
}

type secResult struct {
	PPID int             `json:"ppid"`
	SEC2 obs.Observation `json:"SEC-2"`
	SEC5 obs.Observation `json:"SEC-5"`
}

// runSecProc runs SEC-2 and SEC-5 in a run started by script under a sh that stays alive, and returns the sh's PID
// and the run's observations.
func runSecProc(t *testing.T, script string, extra ...string) (int, secResult) {
	t.Helper()
	dir := t.TempDir()
	cmd := exec.Command("/bin/sh", "-c", script, os.Args[0], scratchDir(t, testOwner), uidArg())
	cmd.Env = append(os.Environ(), append([]string{"SANDPROBE_TEST_WRAP=1", "SANDPROBE_TEST_RUN=secproc", "SANDPROBE_TEST_DIR=" + dir}, extra...)...)
	cmd.Stdin = strings.NewReader(testTok + " " + testOwner + "\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	var res secResult
	b, err := os.ReadFile(filepath.Join(dir, "obs.json"))
	if err != nil || json.Unmarshal(b, &res) != nil {
		t.Fatalf("no observations: %v", err)
	}
	return cmd.Process.Pid, res
}

func target(o obs.Observation, pid int, file string) *obs.Target {
	if o.Proof == nil {
		return nil
	}
	for i, tg := range o.Proof.Targets {
		if tg.Name == "/proc/"+strconv.Itoa(pid)+"/"+file {
			return &o.Proof.Targets[i]
		}
	}
	return nil
}

func ptraceScope() string {
	b, err := os.ReadFile("/proc/sys/kernel/yama/ptrace_scope")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// LNC-3: SEC-2 and SEC-5 skip the wrapper, their direct parent running the probe's own file, and nothing else: the sh
// above it is still counted. A run started straight from sh skips nothing, and a wrapper that dies between the pin
// and the second check leaves both unknown.
func TestWrappedRunSkipsOnlyItsWrapper(t *testing.T) {
	const wrapped = `"$0" -wrap "$1" -expect-uid "$2"; :` // "; :" keeps the sh alive above the wrapper
	sh, res := runSecProc(t, wrapped)
	wrapper := res.PPID
	if wrapper == sh || wrapper <= 1 {
		t.Fatalf("the run's parent %d isn't the wrapper under sh %d", wrapper, sh)
	}
	for id, o := range map[string]obs.Observation{"SEC-2": res.SEC2, "SEC-5": res.SEC5} {
		file := map[string]string{"SEC-2": "environ", "SEC-5": "mem"}[id]
		if target(o, wrapper, file) != nil || strings.Contains(o.Evidence, "/proc/"+strconv.Itoa(wrapper)+"/") {
			t.Errorf("%s listed the wrapper: %+v", id, o)
		}
		if o.Result != obs.Unknown && !strings.Contains(o.Reason, "PID "+strconv.Itoa(wrapper)+",") {
			t.Errorf("%s doesn't record the wrapper's skip: %q", id, o.Reason)
		}
	}
	if tg := target(res.SEC2, sh, "environ"); res.SEC2.Result != obs.Finding || tg == nil || tg.State != "found" {
		t.Errorf("SEC-2 must still find the sh above the wrapper: %+v", res.SEC2)
	}
	switch tg := target(res.SEC5, sh, "mem"); {
	case ptraceScope() == "" || ptraceScope() == "0":
		if res.SEC5.Result != obs.Finding || tg == nil || tg.State != "found" {
			t.Errorf("SEC-5 must still find the sh above the wrapper: %+v", res.SEC5)
		}
	case res.SEC5.Result != obs.Unknown && (tg == nil || tg.State == "found"):
		// Yama refuses a non-descendant's memory: the sh is listed, refused, never found and never left out
		t.Errorf("under ptrace_scope %s, SEC-5 must list the sh as refused: %+v", ptraceScope(), res.SEC5)
	}

	// Straight from sh: the parent is sh, counted, and nothing is skipped.
	sh, res = runSecProc(t, `"$0" -expect-uid "$2"; :`)
	if tg := target(res.SEC2, sh, "environ"); res.SEC2.Result != obs.Finding || tg == nil || tg.State != "found" ||
		strings.Contains(res.SEC2.Reason+res.SEC5.Reason, "LNC-3") {
		t.Errorf("a run straight from sh skipped its parent: %+v %+v", res.SEC2, res.SEC5)
	}

	// The wrapper dies between SEC-2's pin and its second check: SEC-2 is unknown. SEC-5, after it, is unknown too,
	// or, with the wrapper gone from /proc, skips nothing and counts every process: never a skip it can't stand by.
	_, res = runSecProc(t, wrapped, "SANDPROBE_TEST_KILL_PARENT=1")
	if res.SEC2.Result != obs.Unknown || !strings.Contains(res.SEC2.Reason, "LNC-3") {
		t.Errorf("SEC-2 when its wrapper died mid-check: %+v", res.SEC2)
	}
	if res.SEC5.Result != obs.Unknown && strings.Contains(res.SEC5.Reason, "LNC-3") {
		t.Errorf("SEC-5 claims a skip after its wrapper died: %+v", res.SEC5)
	}
}
