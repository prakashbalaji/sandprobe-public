//go:build linux

package probe

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"sandprobe/internal/catalog"
	"sandprobe/internal/grade"
	"sandprobe/internal/obs"
)

// These run inside Linux containers (see test/probe.sh), once as nobody and once as root.

var root = os.Geteuid() == 0

func TestReadCheck(t *testing.T) {
	dir := t.TempDir()
	mk := func(name string, body string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		os.Chmod(p, mode)
		return p
	}
	full, empty, locked := mk("full", "sandprobe-fake", 0o600), mk("empty", "", 0o600), mk("locked", "sandprobe-fake", 0)
	os.Symlink(full, filepath.Join(dir, "abs-link"))
	os.Symlink("full", filepath.Join(dir, "rel-link"))
	os.Symlink(filepath.Join(dir, "gone"), filepath.Join(dir, "dangling"))
	os.Symlink("loop-b", filepath.Join(dir, "loop-a"))
	os.Symlink("loop-a", filepath.Join(dir, "loop-b"))
	syscall.Mkfifo(filepath.Join(dir, "fifo"), 0o600)
	defer os.Chmod(locked, 0o600)

	cases := []struct {
		path     string
		state    string
		nonEmpty bool
		unknown  bool
	}{
		{full, "found", true, false},
		{empty, "found", false, false},
		{filepath.Join(dir, "abs-link"), "found", true, false},
		{filepath.Join(dir, "rel-link"), "found", true, false},
		{filepath.Join(dir, "missing"), "absent", false, false},
		{filepath.Join(dir, "dangling"), "", false, true},
		{filepath.Join(dir, "loop-a"), "", false, true},
		{filepath.Join(dir, "fifo"), "", false, true},
	}
	if !root {
		cases = append(cases, struct {
			path     string
			state    string
			nonEmpty bool
			unknown  bool
		}{locked, "refused", false, false})
	}
	for _, c := range cases {
		tg, ne, err := readCheck(c.path, c.path)
		switch {
		case c.unknown:
			if !errors.Is(err, errUnknowable) {
				t.Errorf("%s: want unknowable, got %+v %v", c.path, tg, err)
			}
		case err != nil:
			t.Errorf("%s: %v", c.path, err)
		case tg.State != c.state || ne != c.nonEmpty:
			t.Errorf("%s: want %s nonEmpty=%v, got %+v nonEmpty=%v", c.path, c.state, c.nonEmpty, tg, ne)
		case c.state == "absent" && (tg.Errno != "ENOENT" || !tg.ParentSearchable):
			t.Errorf("%s: absence not verified: %+v", c.path, tg)
		}
	}
	// the FIFO was never opened: a writer would block forever if it had been, so this returning at all is the check
}

// SBX-2: a filesystem that refuses O_NOATIME (Docker Desktop's file sharing) must not turn a readable file into a
// refusal, while a real EPERM from the file still is one.
func TestReadCheckNoatimeRefused(t *testing.T) {
	p := filepath.Join(t.TempDir(), "env")
	if err := os.WriteFile(p, []byte("sandprobe-fake"), 0o600); err != nil {
		t.Fatal(err)
	}
	real := sysReopen
	defer func() { sysReopen = real }()
	var withFlag int
	sysReopen = func(path string, flags int, mode uint32) (int, error) {
		if flags&syscall.O_NOATIME != 0 {
			withFlag++
			return -1, syscall.EPERM
		}
		return real(path, flags, mode)
	}
	if tg, ne, err := readCheck(p, p); err != nil || tg.State != "found" || !ne || withFlag != 1 {
		t.Fatalf("a refused O_NOATIME hid a readable file: %+v nonEmpty=%v err=%v (asked with the flag %d times)", tg, ne, err, withFlag)
	}
	sysReopen = func(string, int, uint32) (int, error) { return -1, syscall.EPERM }
	if tg, _, err := readCheck(p, p); err != nil || tg.State != "refused" || tg.Errno != "EPERM" {
		t.Fatalf("a real EPERM must stay a refusal: %+v %v", tg, err)
	}
}

func TestWriteCheck(t *testing.T) {
	dir := t.TempDir()
	own := filepath.Join(dir, "own")
	os.WriteFile(own, nil, 0o444)
	cases := map[string]string{
		own:                               "found", // read-only, but its directory is the agent's: replaceable
		filepath.Join(dir, "new"):         "found", // creatable
		"/tmp/sandprobe-not-there":        "found", // creatable in sticky /tmp
		"/etc/sandprobe-not-there":        "absent",
		"/proc/sys/kernel/core_pattern":   "refused",
		"/etc/passwd":                     "refused",
		"/usr/bin/sandprobe-nonexistent":  "absent",
		"/proc/sys/kernel/sandprobe-none": "absent",
	}
	if root {
		cases["/etc/passwd"] = "found"
		cases["/etc/sandprobe-not-there"] = "found"
		cases["/usr/bin/sandprobe-nonexistent"] = "found"
	}
	for path, want := range cases {
		tg, err := writeCheck(path, path)
		if err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		if tg.State != want {
			t.Errorf("%s: want %s, got %+v", path, want, tg)
		}
	}
}

func TestTwins(t *testing.T) {
	tw, err := makeTwins()
	if err != nil {
		t.Fatal(err)
	}
	defer tw.close()
	if !tw.readOK || !tw.writeOK || !tw.permOK || !tw.procOK["environ"] || !tw.procOK["mem"] {
		t.Fatalf("every allowed twin should succeed: %+v", tw)
	}
	if !root && (!tw.readRefused || !tw.writeRefused || !tw.permRefused || !tw.procRefused["environ"] || !tw.procRefused["mem"]) {
		t.Fatalf("as non-root every refusing twin should be refused: %+v", tw)
	}
}

// testEnv is a probe environment over the catalog's discovery rules, with the given planned targets and a fresh home.
func testEnv(t *testing.T, targets map[string][]string) *env {
	tw, err := makeTwins()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tw.close)
	_, discover := catalog.Plan(catalog.IDs())
	return &env{in: Input{Targets: targets, Discover: discover}, root: root, home: t.TempDir(), tw: tw}
}

func chdir(t *testing.T, dir string) {
	old, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(old) })
}

func TestPathDirs(t *testing.T) {
	cases := map[string][]string{".:/usr/bin": {"/w"}, ":/usr/bin": {"/w"}, "bin:/usr/bin": {"/w/bin"},
		"/opt/x:/usr/bin:/evil": {"/opt/x"}, "/usr/local/bin:/usr/bin": nil}
	for path, want := range cases {
		got, err := pathDirs(path, "/w")
		if err != nil || fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("PATH=%s: want %v, got %v %v", path, want, got, err)
		}
	}
	if _, err := pathDirs(".:/usr/bin", ""); err == nil {
		t.Error("a relative entry with no working directory must fail")
	}
}

// PER-2 with the working directory on PATH, as "." or as an empty entry, must find it when it's writable.
func TestPER2WorkingDirectory(t *testing.T) {
	for _, path := range []string{".:/usr/bin", ":/usr/bin"} {
		e := testEnv(t, map[string][]string{"PER-2": {"/usr/local/bin"}})
		chdir(t, t.TempDir())
		t.Setenv("PATH", path)
		ck, _ := catalog.Get("PER-2")
		if o := writable(e, ck); o.Result != obs.Finding {
			t.Errorf("PATH=%s with a writable working directory: want a finding, got %+v", path, o)
		}
	}
}

func TestSocketCheck(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "ctl.sock")
	fd, _ := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err := syscall.Bind(fd, &syscall.SockaddrUnix{Name: sock}); err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	os.Chmod(sock, 0o777)
	file := filepath.Join(dir, "plain")
	os.WriteFile(file, nil, 0o666)

	if tg, how, err := socketCheck(sock, sock); err != nil || tg.State != "found" || how != "" {
		t.Errorf("a socket the agent may write: want found, got %+v %q %v", tg, how, err)
	}
	if tg, _, err := socketCheck("missing", filepath.Join(dir, "missing.sock")); err != nil || tg.State != "absent" {
		t.Errorf("a missing socket in a writable directory: want absent, got %+v %v", tg, err)
	}
	if _, _, err := socketCheck(file, file); !errors.Is(err, errUnknowable) {
		t.Errorf("a regular file at a socket path: want unknowable, got %v", err)
	}
	// the agent's own socket at mode 0: no write permission now, but its owner can give itself one (TWN-4)
	os.Chmod(sock, 0)
	if tg, how, err := socketCheck(sock, sock); err != nil || tg.State != "found" || !root && !strings.Contains(how, "which it owns") {
		t.Errorf("the agent's own socket at mode 0: want found (as it owns it, unless root writes it outright), got %+v %q %v", tg, how, err)
	}
	// AMP-4 over a missing socket whose directory is writable: absent, never a control_socket finding
	e := testEnv(t, map[string][]string{"AMP-4": {filepath.Join(dir, "docker.sock")}})
	ck, _ := catalog.Get("AMP-4")
	if o := sockets(e, ck); o.Result != obs.Absent {
		t.Errorf("AMP-4 with no socket: want absent, got %+v", o)
	}
}

// An unreadable directory in a discovery rule's way makes SEC-3 unknown, never a pass or an absence.
func TestDiscoveryErrors(t *testing.T) {
	if root {
		t.Skip("root reads every directory")
	}
	e := testEnv(t, map[string][]string{"SEC-3": nil})
	hidden := filepath.Join(e.home, "project") // searchable, not listable: a reachable .env can't be ruled out below it
	os.Mkdir(hidden, 0o700)
	os.WriteFile(filepath.Join(hidden, ".env"), []byte("sandprobe-fake"), 0o644)
	os.Chmod(hidden, 0o311)
	defer os.Chmod(hidden, 0o700)
	sealed := filepath.Join(e.home, "sealed") // not searchable: nothing in it is reachable, so no gap
	os.Mkdir(sealed, 0)
	defer os.Chmod(sealed, 0o700)
	chdir(t, t.TempDir())
	ck, _ := catalog.Get("SEC-3")
	if o := sec3(e, ck); o.Result != obs.Unknown {
		t.Errorf("a searchable, unlistable directory under home: want SEC-3 unknown, got %+v", o)
	}
	if _, err := secretFiles(hidden); !errors.Is(err, errHidden) {
		t.Errorf("a searchable, unlistable /run/secrets: want errHidden, got %v", err)
	}
	if got, err := secretFiles(sealed); err != nil || got != nil {
		t.Errorf("an unsearchable directory holds nothing reachable: want empty, got %v %v", got, err)
	}
	if got, err := secretFiles(filepath.Join(e.home, "nope")); err != nil || got != nil {
		t.Errorf("a missing directory is empty, not an error: %v %v", got, err)
	}
	ssh := filepath.Join(e.home, ".ssh")
	os.Mkdir(ssh, 0o311)
	defer os.Chmod(ssh, 0o700)
	if _, err := sshKeys(e.home); !errors.Is(err, errHidden) {
		t.Errorf("a searchable, unlistable ~/.ssh: want errHidden, got %v", err)
	}
	// at the last level, a hidden directory's .env is checked by name instead
	deep := filepath.Join(t.TempDir(), "a", "b")
	os.MkdirAll(deep, 0o700)
	os.WriteFile(filepath.Join(deep, ".env"), []byte("sandprobe-fake"), 0o644)
	os.Chmod(deep, 0o311)
	defer os.Chmod(deep, 0o700)
	if got, err := dotenvs("", filepath.Dir(filepath.Dir(deep))); err != nil || len(got) != 1 {
		t.Errorf("a hidden directory at depth 2: want its .env by name, got %v %v", got, err)
	}
}

// Symlinked directories are followed within the depth bound; dangling links are skipped; loops are unknown; a
// cycle back to an ancestor is walked once; and only ENOENT means a hidden .env is absent.
func TestDotenvSymlinks(t *testing.T) {
	home := t.TempDir()
	real := filepath.Join(home, "releases", "v1")
	os.MkdirAll(real, 0o755)
	os.WriteFile(filepath.Join(real, ".env"), []byte("sandprobe-fake"), 0o644)
	os.MkdirAll(filepath.Join(home, "project"), 0o755)
	os.Symlink(real, filepath.Join(home, "project", "current"))
	os.Symlink("/nonexistent", filepath.Join(home, "dead"))
	os.Symlink("..", filepath.Join(home, "project", "up"))
	got, err := dotenvs(home, "")
	want := filepath.Join(home, "project", "current", ".env")
	found := false
	for _, p := range got {
		found = found || p == want
	}
	if err != nil || !found {
		t.Fatalf("a .env behind home/project/current: want %s, got %v %v", want, got, err)
	}
	e := testEnv(t, map[string][]string{"SEC-3": nil})
	e.home = home
	chdir(t, t.TempDir())
	ck, _ := catalog.Get("SEC-3")
	if o := sec3(e, ck); o.Result != obs.Finding {
		t.Errorf("SEC-3 with a .env behind a symlinked directory: want a finding, got %+v", o)
	}

	// a working directory inside home: its .env two levels down is in scope, though walking home reaches it too deep
	nested := t.TempDir()
	os.MkdirAll(filepath.Join(nested, "project", "x", "y"), 0o755)
	os.WriteFile(filepath.Join(nested, "project", "x", "y", ".env"), []byte("sandprobe-fake"), 0o644)
	if got, err := dotenvs(nested, filepath.Join(nested, "project")); err != nil || len(got) != 1 {
		t.Errorf("cwd nested in home, .env two below cwd: want it found, got %v %v", got, err)
	}
	// the same directory reached first through a deeper symlink path, then directly with more depth left
	order := t.TempDir()
	os.MkdirAll(filepath.Join(order, "a"), 0o755)
	os.MkdirAll(filepath.Join(order, "c", "d"), 0o755)
	os.WriteFile(filepath.Join(order, "c", "d", ".env"), []byte("sandprobe-fake"), 0o644)
	os.Symlink(filepath.Join(order, "c"), filepath.Join(order, "a", "link")) // "a" sorts before "c": the deep path comes first
	if got, err := dotenvs(order, ""); err != nil || len(got) != 1 || got[0] != filepath.Join(order, "c", "d", ".env") {
		t.Errorf("a directory first reached too deep, then shallower: want c/d/.env, got %v %v", got, err)
	}

	loopy := t.TempDir()
	os.Symlink("self", filepath.Join(loopy, "self"))
	if _, err := dotenvs(loopy, ""); !errors.Is(err, errUnknowable) {
		t.Errorf("a symlink loop: want unknowable, got %v", err)
	}

	hidden := filepath.Join(t.TempDir(), "a", "b")
	os.MkdirAll(hidden, 0o700)
	os.Chmod(hidden, 0o311)
	defer os.Chmod(hidden, 0o700)
	lstat = func(string, *syscall.Stat_t) error { return syscall.EIO }
	defer func() { lstat = syscall.Lstat }()
	if !root {
		if _, err := dotenvs("", filepath.Dir(filepath.Dir(hidden))); err == nil {
			t.Error("an lstat fault on a hidden .env must fail discovery, not read as absent")
		}
	}
}

// The working directory can be "/": a readable /.env there must be found, and walking "/" must complete.
func TestDotenvFromRoot(t *testing.T) {
	if _, err := dotenvs("", "/"); err != nil {
		t.Fatalf("walking / should complete as uid %d: %v", os.Geteuid(), err)
	}
	if !root {
		return
	}
	if err := os.WriteFile("/.env", []byte("sandprobe-fake"), 0o644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove("/.env")
	e := testEnv(t, map[string][]string{"SEC-3": nil})
	chdir(t, "/")
	ck, _ := catalog.Get("SEC-3")
	if o := sec3(e, ck); o.Result != obs.Finding || !strings.Contains(o.Evidence, "/.env") {
		t.Errorf("cwd=/ with a readable /.env: want a SEC-3 finding, got %+v", o)
	}
}

func TestParseNetTable(t *testing.T) {
	header := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	good := header + "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0 100 0 0 10 0\n"
	rows, err := parseNetTable(strings.NewReader(good))
	if err != nil || len(rows) != 1 || rows[0].port != 8080 || !rows[0].listen || rows[0].uid != "1000" {
		t.Fatalf("a good table: got %+v %v", rows, err)
	}
	for name, table := range map[string]string{
		"a truncated row":   header + "   0: 0100007F:1F90 00000000:0000 0A\n",
		"a bad port":        header + "   0: 0100007F:ZZZZ 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345\n",
		"no header at all":  "",
		"a three-hex state": header + "   0: 0100007F:1F90 00000000:0000 0A0 00000000:00000000 00:00000000 00000000  1000        0 12345\n",
	} {
		if _, err := parseNetTable(strings.NewReader(table)); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

// TestNet runs against a canary container (test/net.sh): SANDPROBE_NET=open on the canary's network, or none.
func TestNet(t *testing.T) {
	mode, ip := os.Getenv("SANDPROBE_NET"), os.Getenv("SANDPROBE_CANARY_IP")
	if mode == "" {
		t.Skip("run by test/net.sh")
	}
	e := testEnv(t, nil)
	ln, _ := net.Listen("tcp4", "127.0.0.1:0")
	defer ln.Close()
	e.start, e.ownPort = time.Now(), ln.Addr().(*net.TCPAddr).Port
	e.in.CanaryDomain, e.in.CanaryPin = "sandprobe.test", os.Getenv("SANDPROBE_CANARY_PIN")
	e.in.Endpoints = map[string]string{"EGR-2": ip + ":443", "EGR-5.22": ip + ":22", "EGR-5.53u": ip + ":53", "EGR-1": "n-egr-1.dns.sandprobe.test:53"}
	e.in.CheckNonces = map[string]string{"EGR-2": "n-egr-2", "EGR-5.22": "n-egr-5-22", "EGR-5.53u": "n-egr-5-53u", "EGR-1": "n-egr-1"}
	get := func(id string) *catalog.Check { c, _ := catalog.Get(id); return c }
	show := func(name string, v any) { b, _ := json.Marshal(v); t.Logf("%s: %s", name, b) }

	switch mode {
	case "open":
		o := egrDirect(e, get("EGR-2"))
		show("EGR-2", o.Attempts)
		if a := o.Attempts[0]; a.Outcome != "connected" || !a.LoopbackTwin || e.intercepted {
			t.Errorf("EGR-2 on an open network: want connected with its twin and no interception, got %+v", a)
		}
		o = egrDirect(e, get("EGR-5.22"))
		show("EGR-5.22", o.Attempts)
		if o.Attempts[0].Outcome != "connected" {
			t.Errorf("EGR-5.22: want connected, got %+v", o.Attempts[0])
		}
		show("EGR-5.53u", egrUDP(e, get("EGR-5.53u")).Attempts)
		a := e.tcpTry(ip+":9", nil)
		show("closed port", a)
		if a.Outcome != "refused" || !a.SynSent || a.Immediate {
			t.Errorf("a closed port on the canary: want refused with SYN_SENT seen, got %+v", a)
		}
		a = e.tcpTry("172.30.99.99:443", nil)
		show("no such host", a)
		if (a.Outcome != "hostunreach" && a.Outcome != "timeout") || !a.SynSent {
			t.Errorf("a host that isn't there: want hostunreach or timeout with SYN_SENT seen, got %+v", a)
		}
		// EGR-3 through an approved loopback proxy: exactly one CONNECT, to the canary, and the TLS echo completes
		// through a proxy whose answer is split across writes.
		p := startProxy(t)
		t.Setenv("HTTPS_PROXY", "http://"+p.ln.Addr().String())
		e.in.Proxy, e.in.AllowLocal = p.ln.Addr().String(), true
		e.in.Endpoints["EGR-3"], e.in.CheckNonces["EGR-3"] = ip+":443", "n-egr-3"
		o = egrProxy(e, get("EGR-3"))
		show("EGR-3", o.Attempts)
		if n, dests := p.seen(); len(o.Attempts) != 1 || o.Attempts[0].Outcome != "connected" || n != 1 || len(dests) != 1 || dests[0] != ip+":443" {
			t.Errorf("EGR-3: want one attempt through one CONNECT to the canary, got %+v, %d connections, %v", o.Attempts, n, dests)
		}
		c, err := net.Dial("tcp4", p.ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		tun, err := connect(c, ip+":443")
		if err == nil {
			err = e.tlsUse("n-egr-3-echo")(tun)
		}
		c.Close()
		if err != nil || e.intercepted {
			t.Errorf("the TLS echo through the proxy: %v (intercepted %v)", err, e.intercepted)
		}
		e.in.CanaryPin = strings.Repeat("0", 64)
		egrDirect(e, get("EGR-2"))
		if !e.intercepted || egrIntercept(e, get("EGR-4")).Result != obs.Finding {
			t.Error("a key other than the pin must be interception (EGR-4)")
		}
	case "none":
		o := egrDirect(e, get("EGR-2"))
		show("EGR-2", o.Attempts)
		if a := o.Attempts[0]; !a.Immediate || a.Outcome != "netunreach" || a.RouteLookup != "none" || !a.LoopbackTwin {
			t.Errorf("EGR-2 with no network: want an immediate netunreach the route lookup agrees with, and the twin, got %+v", a)
		}
	}
}

// TestRunGrades runs the whole probe and grades its document with the approved grader: the contract, end to end.
func TestRunGrades(t *testing.T) {
	os.Setenv("SANDPROBE_TWIN", "1")
	chdir(t, t.TempDir())
	ids := slices.DeleteFunc(catalog.IDs(), func(id string) bool { return id == "PER-5" }) // one box, no reset: skipped
	targets, discover := catalog.Plan(ids)
	nonces, endpoints := map[string]string{}, map[string]string{}
	for _, c := range catalog.Checks {
		if c.Canary != nil {
			nonces[c.ID], endpoints[c.ID] = "n-"+c.ID, fmt.Sprintf("203.0.113.10:%d", c.Canary.Port)
		}
	}
	in := Input{RunID: "r1", Nonce: "n1", BoxID: "box-1", Mode: "exec", Selected: ids, Targets: targets, Discover: discover,
		CheckNonces: nonces, Endpoints: endpoints, Proxy: "203.0.113.20:3128"}
	d, err := Run(in)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(d)
	m := obs.Manifest{RunID: "r1", Nonce: "n1", BoxID: "box-1", ProbeSHA256: d.ProbeSHA256, Mode: "exec", Selected: ids,
		Targets: targets, Discover: discover, CheckNonces: nonces, Endpoints: endpoints, Proxy: in.Proxy,
		Skipped: map[string]string{"PER-5": "the provider's reset leaves no storage to test"}}
	r := grade.GradeBytes(m, b, nil)
	if !r.Valid {
		t.Fatalf("the grader rejected the probe's document: %s", r.Invalid)
	}
	for _, o := range r.Outcomes {
		t.Logf("%-10s %-10s %-22s %s%s", o.ID, o.Result, o.Variant, o.Evidence, o.Reason)
	}
	t.Logf("grade %s complete=%v (uid %d, NoNewPrivs %d, setuid %d files)", r.Letter, r.Complete, d.Identity.UID,
		*d.Identity.NoNewPrivs, len(d.Identity.SetuidScan.Files))
	get := func(id string) grade.Outcome {
		for _, o := range r.Outcomes {
			if o.ID == id {
				return o
			}
		}
		return grade.Outcome{}
	}
	if root {
		if o := get("AMP-2"); o.Variant != "root" || r.Letter != "F" {
			t.Fatalf("as root AMP-2 must be root and the grade F, got %+v and %s", o, r.Letter)
		}
		return
	}
	for _, id := range []string{"SEC-1", "PER-3", "AMP-8.sys"} {
		if o := get(id); o.Result != obs.Pass {
			t.Errorf("%s should pass for nobody in a plain container, got %+v", id, o)
		}
	}
	if o := get("SEC-2"); o.Result != obs.ScopedOut && o.Result != obs.Pass {
		t.Errorf("SEC-2 should pass or be scoped out, got %+v", o)
	}
	if o := get("EGR-2"); o.Result != obs.Unknown {
		t.Errorf("with no canary EGR-2 must be unknown, got %+v", o)
	}
}

// /run/secrets as Kubernetes and EKS lay it out: directories of symlinks, walked to every file, never a directory
// taken for a file; a cycle ends; a tree deeper than the walk fails discovery.
func TestSecretFiles(t *testing.T) {
	root := t.TempDir()
	sa := filepath.Join(root, "kubernetes.io", "serviceaccount")
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(sa, "..2026_11_09"), 0o755))
	must(os.WriteFile(filepath.Join(sa, "..2026_11_09", "token"), []byte("x"), 0o644))
	must(os.Symlink("..2026_11_09", filepath.Join(sa, "..data")))
	must(os.Symlink("..data/token", filepath.Join(sa, "token")))
	must(os.MkdirAll(filepath.Join(root, "eks.amazonaws.com", "serviceaccount"), 0o755))
	must(os.WriteFile(filepath.Join(root, "eks.amazonaws.com", "serviceaccount", "token"), []byte("x"), 0o644))
	must(os.WriteFile(filepath.Join(root, "db-password"), []byte("x"), 0o644))
	must(os.Symlink("/nowhere", filepath.Join(root, "gone")))
	must(os.Symlink(".", filepath.Join(root, "loop")))
	got, err := secretFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{filepath.Join(sa, "token"), filepath.Join(sa, "..2026_11_09", "token"),
		filepath.Join(root, "eks.amazonaws.com", "serviceaccount", "token"), filepath.Join(root, "db-password"), filepath.Join(root, "gone")} {
		if !slices.Contains(got, want) {
			t.Errorf("want %s among the targets, got %v", want, got)
		}
	}
	for _, p := range got {
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			t.Errorf("a directory taken for a file: %s", p)
		}
	}
	must(os.MkdirAll(filepath.Join(root, "a", "b", "c", "d", "e"), 0o755))
	if _, err := secretFiles(root); err == nil {
		t.Error("a directory deeper than the walk covers must fail discovery")
	}
}

// write_perm counts a refusal only while the agent can't make the path writable either (TWN-4): a mode it can change,
// a uid it can become, or a capability it can raise makes the path found, saying how. Neither counts in a read-only
// /proc/sys. TestModelAgainstKernel covers the combinations.
func TestWriteOwnerPower(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	os.Mkdir(home, 0o755)
	rc := filepath.Join(home, ".bashrc")
	os.WriteFile(rc, nil, 0o444)
	os.Chmod(home, 0o555)
	t.Cleanup(func() { os.Chmod(home, 0o755) })
	// under /tmp the agent can replace its own temporary directory outright; the fixture evidence-owned, and the
	// model's "owned read-only directory" case, show the owner's change of mode where nothing else reaches
	if tg, _, err := writeHow("~/.bashrc", rc); err != nil || tg.State != "found" {
		t.Errorf("a file of its own in its own 0555 directory: want found, got %+v %v", tg, err)
	}
	if root {
		return
	}
	defer func(f func() uint64) { agentCaps = f }(agentCaps)
	for caps, want := range map[uint64]string{
		0:              "",
		capFowner:      "changing the mode of /usr/bin/ls, with CAP_FOWNER",
		capChown:       "changing the mode of /usr/bin/ls, taking it over with CAP_CHOWN",
		capDacOverride: "raising CAP_DAC_OVERRIDE",
		capSetuid:      "as its owner, uid 0 (CAP_SETUID)",
		capSetgid:      "", // /usr/bin and ls are no group's to write
		1 << 4:         "", // CAP_FSETID changes no mode
	} {
		agentCaps = func() uint64 { return caps }
		tg, how, err := writeHow("/usr/bin/ls", "/usr/bin/ls")
		if err != nil || (want == "") != (how == "") || !strings.Contains(how, want) || (want == "") != (tg.State == "refused") {
			t.Errorf("caps %#x: want %q, got %+v %q %v", caps, want, tg, how, err)
		}
		// a read-only /proc/sys (the usual container) stops every power; TestSetuidProcfs covers a writable one
		if tg, how, _ := writeHow("/proc/sys/kernel/sysrq", "/proc/sys/kernel/sysrq"); readOnly("/proc/sys/kernel/sysrq") &&
			(tg.State != "refused" || how != "") {
			t.Errorf("caps %#x: a kernel setting on a read-only mount: want refused, got %+v %q", caps, tg, how)
		}
	}
}

// The shared write_perm judgement (TWN-4): a check that found nothing is unknown while the agent holds a capability
// that reaches past file permissions; a proof-class check is never found from a mode the agent would first change.
func TestJudgeWrite(t *testing.T) {
	if root {
		t.Skip("root can write the targets outright")
	}
	defer func(f func() uint64) { agentCaps = f }(agentCaps)
	e := testEnv(t, map[string][]string{"PER-3": {"/etc/systemd/system", "/etc/cron.d"}})
	ck, _ := catalog.Get("PER-3")
	agentCaps = func() uint64 { return 0 }
	if o := writable(e, ck); o.Result != obs.Pass {
		t.Fatalf("no capabilities, root's directories: want a pass, got %+v", o)
	}
	agentCaps = func() uint64 { return 1 << 21 }
	if o := writable(e, ck); o.Result != obs.Unknown || !strings.Contains(o.Reason, "CAP_SYS_ADMIN") {
		t.Errorf("CAP_SYS_ADMIN: want unknown naming it, got %+v", o)
	}
	agentCaps = func() uint64 { return 1 << 3 }
	if o := writable(e, ck); o.Result != obs.Finding || !strings.Contains(o.Evidence, "with CAP_FOWNER") {
		t.Errorf("CAP_FOWNER: want a finding saying how, got %+v", o)
	}
	sys, _ := catalog.Get("AMP-8.sys")
	ts := []obs.Target{{Name: "/proc/sys/kernel/sysrq", State: "found"}}
	o := e.judgeWrite(sys, ts, nil, map[string]string{"/proc/sys/kernel/sysrq": "it can make it writable, as it owns it"},
		func([]obs.Target, []string) (string, string) { return "writable_sysctl", "x" })
	if o.Result != obs.Unknown {
		t.Errorf("a kernel setting the agent could only make writable: want unknown, never a proof, got %+v", o)
	}
}

// TWN-4 on the read side: a refusal counts only while the agent can't make the file readable either. Its own file at
// mode 0000 can't pass, nor anything refused while it holds a read power; an absence stays a fact under one; a process file's
// refusal can't pass while the agent holds a power over ptrace's rules. Nothing is read to find out.
func TestRefusalsHold(t *testing.T) {
	if root {
		t.Skip("root opens every file outright")
	}
	defer func(f func() uint64) { agentCaps = f }(agentCaps)
	agentCaps = func() uint64 { return 0 }
	own := filepath.Join(t.TempDir(), "credentials")
	os.WriteFile(own, []byte("sandprobe-fake"), 0o600)
	os.Chmod(own, 0)
	t.Cleanup(func() { os.Chmod(own, 0o600) })
	sec3, _ := catalog.Get("SEC-3")
	e := testEnv(t, nil)
	judge := func(name, path string) obs.Observation {
		tg, _, err := readCheck(name, path)
		if err != nil {
			t.Fatal(err)
		}
		return e.judge(sec3, []obs.Target{tg}, nil, true, true, func([]obs.Target) (string, string) { return "nonempty", "x" })
	}
	if o := judge(own, own); o.Result != obs.Unknown || !strings.Contains(o.Reason, "changing the mode of "+own+", which it owns") {
		t.Errorf("the agent's own file at mode 0000: want unknown, as it owns it, got %+v", o)
	}
	if o := judge("/etc/shadow", "/etc/shadow"); o.Result != obs.Pass { // root's, and nothing lets the agent past it
		t.Errorf("root's /etc/shadow, no capabilities: want a pass, got %+v", o)
	}
	for _, caps := range []uint64{capDacReadSearch, capDacOverride, capFowner, capChown, capSetuid, capSetgid, capSysAdmin} {
		agentCaps = func() uint64 { return caps }
		if o := judge("/etc/shadow", "/etc/shadow"); o.Result != obs.Unknown || !strings.Contains(o.Reason, capList(caps)) {
			t.Errorf("caps %#x: want unknown naming %s, got %+v", caps, capList(caps), o)
		}
	}
	// a read power doesn't make a missing file exist; CAP_SYS_ADMIN, which can unmount what hides one, is
	// TestReachPastEarlyReturns'
	agentCaps = func() uint64 { return capDacReadSearch | capFowner | capSetuid }
	absent := obs.Target{Name: "/nowhere/credentials", State: "absent", Errno: "ENOENT", ParentSearchable: true}
	if o := e.judge(sec3, []obs.Target{absent}, nil, true, true, nil); o.Result == obs.Unknown {
		t.Errorf("an absent file stays absent under a read power: want it judged as before, got %+v", o)
	}
	sec2, _ := catalog.Get("SEC-2")
	refused := obs.Target{Name: "/proc/1/environ", State: "refused", Errno: "EACCES"}
	for caps, want := range map[uint64]string{0: obs.Pass, capSysPtrace: obs.Unknown, capSetuid: obs.Unknown, capDacReadSearch: obs.Pass} {
		agentCaps = func() uint64 { return caps }
		if o := e.judge(sec2, []obs.Target{refused}, nil, true, true, nil); o.Result != want {
			t.Errorf("a process file refused, caps %#x: want %s, got %+v", caps, want, o)
		}
	}
}

// TWN-1's file-read and read-permission twins under a capability that passes the read call itself: the probe's own
// 0000 file opens, so the refusing side fails and no non-root pass can stand (GRD-5). test/probe.sh runs this as
// nobody holding CAP_DAC_READ_SEARCH and CAP_DAC_OVERRIDE.
func TestTwinReadPower(t *testing.T) {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		t.Fatal(err)
	}
	if root || data[0].Effective&(capDacReadSearch|capDacOverride) == 0 {
		t.Skip("needs a non-root agent holding CAP_DAC_READ_SEARCH or CAP_DAC_OVERRIDE")
	}
	tw, err := makeTwins()
	if err != nil {
		t.Fatal(err)
	}
	defer tw.close()
	if tw.readRefused || tw.permRefused {
		t.Errorf("the probe's own 0000 file must open for an agent passing the read call: read refused %v, perm refused %v",
			tw.readRefused, tw.permRefused)
	}
	if o := (&env{tw: tw}).judge(&catalog.Check{ID: "SEC-3", Mechanism: "file_read", Kind: catalog.TwoSided}, nil, nil,
		tw.readOK, tw.readRefused, nil); o.Result == obs.Pass && o.Proof.TwinRefused {
		t.Errorf("a pass with the refusing twin shown: %+v", o)
	}
}

// TWN-4's identity powers in procfs (test/probe.sh runs this as nobody in a container whose /proc/sys is writable):
// no mode can change there, but CAP_SETUID makes the agent uid 0, which proc gives a sysctl's owner bits, so a kernel
// setting root may write is writable to it. AMP-8's findings are proofs, so that leaves the check unknown, never a
// pass. On a read-only /proc/sys it stays a pass: the mount stops everyone.
func TestSetuidProcfs(t *testing.T) {
	if root {
		t.Skip("root writes a sysctl outright")
	}
	defer func(f func() uint64) { agentCaps = f }(agentCaps)
	e := testEnv(t, map[string][]string{"AMP-8.sys": {"/proc/sys/kernel/sysrq"}})
	ck, _ := catalog.Get("AMP-8.sys")
	agentCaps = func() uint64 { return 0 }
	if o := writable(e, ck); o.Result != obs.Pass {
		t.Fatalf("no capabilities: want a pass, got %+v", o)
	}
	agentCaps = func() uint64 { return capSetuid }
	o := writable(e, ck)
	if readOnly("/proc/sys/kernel/sysrq") {
		if o.Result != obs.Pass {
			t.Errorf("CAP_SETUID, /proc/sys read-only: want a pass, got %+v", o)
		}
		t.Skip("/proc/sys is read-only here; test/probe.sh runs this with it writable")
	}
	if o.Result != obs.Unknown || !strings.Contains(o.Reason, "as uid 0 (CAP_SETUID)") {
		t.Errorf("CAP_SETUID, /proc/sys writable: want unknown naming it, got %+v", o)
	}
}

// TWN-4's everywhere rule comes before every early negative a file check can return: a pass, an allowed absence, a
// scoped_out, AMP-1's absence. Each one, under CAP_SYS_ADMIN, is unknown naming it; with no capability, the same call
// returns its negative, so each early return is really reached.
func TestReachPastEarlyReturns(t *testing.T) {
	if root {
		t.Skip("root finds the write targets outright")
	}
	defer func(f func() uint64) { agentCaps = f }(agentCaps)
	chdir(t, t.TempDir())
	missing := filepath.Join(t.TempDir(), "missing")
	t.Setenv("PATH", t.TempDir())
	e := testEnv(t, map[string][]string{"AMP-4": {missing + ".sock"}, "SEC-3": {missing}, "AMP-1": {missing + "-sudo"},
		"PER-3": {"/etc/systemd/system"}, "AMP-8.sys": {"/proc/sys/kernel/sysrq"}})
	get := func(id string) *catalog.Check { ck, _ := catalog.Get(id); return ck }
	for name, run := range map[string]func() obs.Observation{
		"AMP-4 absent":         func() obs.Observation { return sockets(e, get("AMP-4")) },
		"SEC-3 absent":         func() obs.Observation { return sec3(e, get("SEC-3")) },
		"SEC-2 scoped_out":     func() obs.Observation { return secProc(e, get("SEC-2"), "environ") },
		"SEC-5 scoped_out":     func() obs.Observation { return secProc(e, get("SEC-5"), "mem") },
		"AMP-8.blk scoped_out": func() obs.Observation { return amp8blk(e, get("AMP-8.blk")) },
		"AMP-1 absent":         func() obs.Observation { return amp1(e, get("AMP-1")) },
		"PER-3 pass":           func() obs.Observation { return writable(e, get("PER-3")) },
		"AMP-8.sys pass":       func() obs.Observation { return writable(e, get("AMP-8.sys")) },
	} {
		agentCaps = func() uint64 { return 0 }
		if o := run(); o.Result == obs.Unknown || o.Result == obs.Finding {
			t.Errorf("%s, no capability: want its negative, got %+v", name, o)
		}
		agentCaps = func() uint64 { return capSysAdmin }
		if o := run(); o.Result != obs.Unknown || !strings.Contains(o.Reason, "CAP_SYS_ADMIN") {
			t.Errorf("%s, CAP_SYS_ADMIN: want unknown naming it, got %+v", name, o)
		}
	}
}
