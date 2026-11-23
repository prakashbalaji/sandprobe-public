//go:build linux

package probe

import (
	"fmt"
	"io"
	"net"
	"net/textproto"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"sandprobe/internal/catalog"
	"sandprobe/internal/obs"
)

// AMP-1's allow-list: a chain is trusted only when every link and every directory on it is root's and out of the
// agent's reach, and it ends at a root-owned setuid file named sudo; anything else is refused before it runs, and the
// refusal says what failed. The image has no sudo, so what passes is shown by the sudors fixture.
func TestPinSudo(t *testing.T) {
	dir := t.TempDir()
	own := filepath.Join(dir, "sudo")
	os.WriteFile(own, []byte("#!/bin/sh\n"), 0o4755)
	link := filepath.Join(dir, "link")
	os.Symlink("/usr/bin/su", link)
	dangling := filepath.Join(dir, "dangling")
	os.Symlink(filepath.Join(dir, "nowhere"), dangling)
	want := map[string]string{
		own:      fmt.Sprintf("%s is owned by uid %d, not root", dir, os.Geteuid()),
		link:     fmt.Sprintf("the link %s isn't root's (uid %d)", link, os.Geteuid()),
		dangling: "its links can't be followed to a file",
		// root's, in root's directories, but not setuid; the second through two links and /bin's directory link
		"/usr/bin/ls":    "/usr/bin/ls isn't setuid",
		"/usr/bin/pager": "/usr/bin/more isn't setuid",
		// root's and setuid, in root's directories, also through /bin's directory link, but not a sudo
		"/usr/bin/su": "/usr/bin/su isn't named sudo or sudo.ws",
		"/bin/su":     "/usr/bin/su isn't named sudo or sudo.ws",
	}
	if root { // root owns the temporary directory, and can write every directory
		want[own] = "the agent can write " + dir
		want[link] = "the agent can write " + dir
		for _, p := range []string{"/usr/bin/ls", "/usr/bin/pager", "/usr/bin/su", "/bin/su"} {
			want[p] = "the agent can write /usr/bin" // the deepest directory looked in, judged first
		}
		want[link] = "the agent can write /usr/bin"
	}
	for p, reason := range want {
		fd, chain, why := pinSudo(p)
		if why == "" {
			syscall.Close(fd)
			t.Errorf("%s: want it refused, got it pinned as %s", p, chain)
		} else if !strings.Contains(why, reason) {
			t.Errorf("%s: want the refusal to say %q, got %q", p, reason, why)
		}
	}
}

// The walk resolves as the kernel does: every link on the way, a directory's as well as the last name's, followed from
// the directory that holds it and named in the chain; one budget of eight for the whole path.
func TestWalk(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "d2"), 0o755)
	os.WriteFile(filepath.Join(dir, "d2", "f"), nil, 0o644)
	os.Symlink("d2", filepath.Join(dir, "d1"))                         // a directory link, relative
	os.Symlink(filepath.Join(dir, "d1", "f"), filepath.Join(dir, "l")) // a link through it, absolute
	os.Mkdir(filepath.Join(dir, "sub"), 0o755)
	os.Symlink("../d1/f", filepath.Join(dir, "sub", "up")) // .. taken from the directory holding the link
	for p, wantChain := range map[string][]string{
		filepath.Join(dir, "l"):         {filepath.Join(dir, "l"), filepath.Join(dir, "d1", "f"), filepath.Join(dir, "d2", "f")},
		filepath.Join(dir, "sub", "up"): {filepath.Join(dir, "sub", "up"), dir + "/sub/../d1/f", filepath.Join(dir, "d2", "f")},
		"/bin/su":                       {"/bin/su", "/usr/bin/su"},
	} {
		w, err := walkPath(p, true)
		if err != nil {
			t.Errorf("%s: %v", p, err)
			continue
		}
		if !slices.Equal(w.steps, wantChain) || w.nodes[w.last()].path != wantChain[len(wantChain)-1] {
			t.Errorf("%s: want the chain %v, got %v ending at %s", p, wantChain, w.steps, w.nodes[w.last()].path)
		}
		w.close()
	}
	// nine directory links in a row: past SBX-2's eight, never followed to the end
	for i := 1; i <= 9; i++ {
		os.Symlink(fmt.Sprintf("n%d", i+1), filepath.Join(dir, fmt.Sprintf("n%d", i)))
	}
	os.Mkdir(filepath.Join(dir, "n10"), 0o755)
	os.WriteFile(filepath.Join(dir, "n10", "f"), nil, 0o644)
	if _, err := walkPath(filepath.Join(dir, "n1", "f"), true); err == nil || !strings.Contains(err.Error(), "more than 8") {
		t.Errorf("nine directory links: want refused after eight, got %v", err)
	}
}

// Root, or any capability, permitted, effective or inheritable, means no chain is trusted, and the reason names them.
func TestPrivileged(t *testing.T) {
	for _, tc := range []struct {
		euid int
		caps uint64
		want string
	}{
		{1000, 0, ""},
		{1000, 1 << 3, "the agent holds CAP_FOWNER, so"},
		{1000, 1 << 10, "the agent holds CAP_NET_BIND_SERVICE, so"},
		{0, 0, "the agent is root, so"},
		{0, 1<<0 | 1<<21, "the agent is root and holds CAP_CHOWN, CAP_SYS_ADMIN, so"},
		{1000, 1<<41 - 1, "CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH, CAP_FOWNER, CAP_FSETID, CAP_KILL, CAP_SETGID, CAP_SETUID, 33 more, so"},
	} {
		got := privilegedWhy(tc.euid, tc.caps)
		if tc.want == "" && got != "" || !strings.Contains(got, tc.want) {
			t.Errorf("euid %d, caps %#x: want %q, got %q", tc.euid, tc.caps, tc.want, got)
		}
	}
	// read with capget: nobody holds none here, root the container's set
	if why := privileged(); root == (why == "") {
		t.Errorf("as uid %d: got %q", os.Geteuid(), why)
	}
}

// TestMain lets the test binary stand in for sudo: AMP-1 runs a pinned file by descriptor (spawnFD), which can't run a
// #! script while the descriptor stays close-on-exec, so the stand-in is this ELF binary, told by its environment what
// shell script to play.
func TestMain(m *testing.M) {
	if script := os.Getenv("SANDPROBE_TEST_SUDO"); script != "" {
		syscall.Exec("/bin/sh", []string{"sh", "-c", script}, os.Environ())
		os.Exit(127)
	}
	os.Exit(m.Run())
}

// standIn pins this test binary to play script as sudo, and returns its descriptor.
func standIn(t *testing.T, script string) int {
	t.Helper()
	base := sudoEnv
	t.Cleanup(func() { sudoEnv = base })
	sudoEnv = []string{"SANDPROBE_TEST_SUDO=" + script}
	for _, v := range base {
		if !strings.HasPrefix(v, "SANDPROBE_TEST_SUDO=") {
			sudoEnv = append(sudoEnv, v)
		}
	}
	fd, err := syscall.Open(os.Args[0], unixOPath|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	return fd
}

// sudo's listing, read the way AMP-1 reads it, from a pinned descriptor. A stand-in prints each listing.
func TestSudoList(t *testing.T) {
	for _, tc := range []struct{ listing, result, variant string }{
		{"User agent may run the following commands on box:\n    (ALL : ALL) NOPASSWD: ALL\n", obs.Finding, "nopasswd_all"},
		{"    (root) NOPASSWD: SETENV: /usr/bin/apt, /usr/bin/systemctl\n", obs.Finding, "nopasswd_named"},
		{"    (root) NOPASSWD: SETENV: ALL\n", obs.Finding, "nopasswd_all"},
		{"    (ALL : ALL) ALL\n", obs.NotFound, ""},
		{"    (root) NOPASSWD: /usr/bin/curl -H Authorization:sandprobe-fake\n", obs.Finding, "nopasswd_named"},
		{"", obs.NotFound, ""},
	} {
		o := sudoList("sudo", standIn(t, "cat <<'EOF'\n"+tc.listing+"EOF\n"))
		if o.Result != tc.result || o.Variant != tc.variant {
			t.Errorf("%q: want %s %s, got %+v", tc.listing, tc.result, tc.variant, o)
		}
		if strings.Contains(o.Evidence+o.Reason, "sandprobe-fake") || strings.Contains(o.Evidence, "/usr/bin") {
			t.Errorf("a rule's commands reached the observation: %+v", o)
		}
	}
	// a sudo ended by a signal looks like a child that died before its exec: unknown, never not_found
	if o := sudoList("sudo", standIn(t, "kill -KILL $$")); o.Result != obs.Unknown || !strings.Contains(o.Reason, "signal") {
		t.Errorf("a sudo killed by a signal: want unknown, got %+v", o)
	}
	// a #! file can't run from a close-on-exec descriptor, which would hand its interpreter a /proc path to look up
	script := filepath.Join(t.TempDir(), "sudo")
	os.WriteFile(script, []byte("#!/bin/sh\necho '    (ALL) NOPASSWD: ALL'\n"), 0o755)
	fd, err := syscall.Open(script, unixOPath|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if o := sudoList(script, fd); o.Result != obs.Unknown || !strings.Contains(o.Reason, "can't run") {
		t.Errorf("a #! sudo: want unknown, never run, got %+v", o)
	}
}

// sudo's whole run is bounded (SBX-7): output past any pipe buffer is drained, and a sudo that doesn't exit is killed.
func TestSudoListBounded(t *testing.T) {
	defer func(d time.Duration) { checkLimit = d }(checkLimit)
	checkLimit = time.Second
	run := func(script string) (obs.Observation, time.Duration) {
		fd := standIn(t, script)
		start := time.Now()
		o := sudoList("sudo", fd)
		return o, time.Since(start)
	}
	// 200 KB of other lines first, then the rule, then exit: drained, and the rule still found
	o, _ := run("i=0; while [ $i -lt 4000 ]; do echo '    Defaults env_reset, mail_badpass, secure_path=/usr/sbin:/usr/bin:/sbin:/bin'; i=$((i+1)); done\n" +
		"echo '    (ALL) NOPASSWD: ALL'\n")
	if o.Result != obs.Finding || o.Variant != "nopasswd_all" {
		t.Errorf("a long listing: want the rule found, got %+v", o)
	}
	// one line longer than the reader takes: the listing can't be read as rules, so unknown
	if o, _ := run("head -c 100000 /dev/zero | tr '\\0' 'x'; echo\n"); o.Result != obs.Unknown {
		t.Errorf("an unreadable listing: want unknown, got %+v", o)
	}
	// more than a pipe buffer, then it stays alive
	o, took := run("head -c 200000 /dev/zero | tr '\\0' 'x'; echo; sleep 30\n")
	if o.Result != obs.Unknown || took > 3*time.Second {
		t.Errorf("a sudo that doesn't exit: want unknown within the limit, got %+v after %v", o, took)
	}
	// and nothing it started outlives it: no process of ours but the test is left running sleep
	time.Sleep(100 * time.Millisecond)
	if os.Getpid() == 1 { // test/probe.sh runs the tests as PID 1, which inherits orphans: reap them, as an init would
		for {
			if pid, _ := syscall.Wait4(-1, nil, syscall.WNOHANG, nil); pid <= 0 {
				break
			}
		}
	}
	entries, _ := os.ReadDir("/proc")
	for _, d := range entries {
		stat, err := os.ReadFile("/proc/" + d.Name() + "/stat") // "pid (comm) state ..."
		if _, rest, ok := strings.Cut(string(stat), ") "); err == nil && ok && strings.Contains(string(stat), "(sleep)") && rest[0] != 'Z' {
			t.Errorf("pid %s (sleep) outlived the killed sudo", d.Name())
		}
	}
}

// SEC-4's listings, asked independently under one deadline: a service ignoring one request is asked the others, and
// a check cut off by time is unknown, never not_found.
func TestMetaScan(t *testing.T) {
	type key struct{ method, path string }
	role := metaAnswer{code: 200, body: "fixture-role\n"}
	gcp := metaAnswer{code: 200, hdr: textproto.MIMEHeader{"Metadata-Flavor": {"Google"}}, body: "default/\n"}
	for _, tc := range []struct {
		name    string
		answers map[key]any // metaAnswer or error; missing: errNoAnswer
		result  string
		asked   int // requests made; 0 means don't care
	}{
		{"nothing listens", map[key]any{{"PUT", "/latest/api/token"}: errNoConnect}, obs.NotFound, 1},
		{"the token request ignored, IMDSv1 still asked", map[key]any{{"GET", "/latest/meta-data/iam/security-credentials/"}: role},
			obs.Finding, 3},
		{"GCP, only from Google's server", map[key]any{{"GET", "/computeMetadata/v1/instance/service-accounts/"}: gcp}, obs.Finding, 0},
		{"a GCP-shaped listing without Google's header", map[key]any{
			{"GET", "/computeMetadata/v1/instance/service-accounts/"}: metaAnswer{code: 200, body: "default/\n"}}, obs.NotFound, 0},
		{"out of time before the listings", map[key]any{{"PUT", "/latest/api/token"}: errOutOfTime}, obs.Unknown, 1},
		{"a role found, then out of time", map[key]any{{"PUT", "/latest/api/token"}: metaAnswer{code: 200, body: "tok"},
			{"GET", "/latest/meta-data/iam/security-credentials/"}:    role,
			{"GET", "/computeMetadata/v1/instance/service-accounts/"}: errOutOfTime}, obs.Finding, 0},
		{"an answer that isn't a listing", map[key]any{
			{"GET", "/latest/meta-data/iam/security-credentials/"}: metaAnswer{code: 200, body: "<html>"}}, obs.Unknown, 0},
	} {
		asked := 0
		req := func(addr, method, path, host string, h map[string]string, deadline time.Time) (metaAnswer, error) {
			asked++
			switch a := tc.answers[key{method, path}].(type) {
			case metaAnswer:
				return a, nil
			case error:
				return metaAnswer{}, a
			}
			return metaAnswer{}, errNoAnswer
		}
		dial := func(string, time.Time) error { return errNoConnect }
		o := metaScan(time.Now().Add(time.Second), req, dial)
		if o.Result != tc.result || tc.asked > 0 && asked != tc.asked {
			t.Errorf("%s: want %s after %d requests, got %+v after %d", tc.name, tc.result, tc.asked, o, asked)
		}
	}
	// a token that could end its header line is never sent: no request carries a control character, the other
	// listings are still asked, and with nothing found SEC-4 is unknown
	var sent []string
	smuggle := func(addr, method, path, host string, h map[string]string, deadline time.Time) (metaAnswer, error) {
		for _, v := range h {
			sent = append(sent, v)
		}
		if method == "PUT" {
			return metaAnswer{code: 200, body: "tok\r\nGET /latest/meta-data/iam/security-credentials/sandprobe-fixture-role HTTP/1.1"}, nil
		}
		sent = append(sent, path)
		return metaAnswer{}, errNoAnswer
	}
	o := metaScan(time.Now().Add(time.Second), smuggle, func(string, time.Time) error { return errNoConnect })
	for _, v := range sent {
		if strings.ContainsAny(v, "\r\n") || strings.Contains(v, "sandprobe-fixture-role") {
			t.Errorf("injected bytes reached a request: %q", v)
		}
	}
	if o.Result != obs.Unknown || !slices.Contains(sent, "/latest/meta-data/iam/security-credentials/") {
		t.Errorf("an odd token: want IMDSv1 still asked and SEC-4 unknown, got %+v after %v", o, sent)
	}
	// the variables offer ECS, but the deadline has passed: unknown, not not_found
	t.Setenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/credentials/x")
	none := func(string, string, string, string, map[string]string, time.Time) (metaAnswer, error) {
		return metaAnswer{}, errNoConnect
	}
	if o := metaScan(time.Now().Add(time.Second), none, func(string, time.Time) error { return errOutOfTime }); o.Result != obs.Unknown {
		t.Errorf("an offered endpoint cut off by time: want unknown, got %+v", o)
	}
}

// AMP-1 with no sudo anywhere is a verified absence (KND-2), with its discovery reported.
func TestAMP1Absent(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sudo"); err == nil {
		t.Skip("sudo is installed here")
	}
	ck, _ := catalog.Get("AMP-1")
	targets, discover := catalog.Plan([]string{"AMP-1"})
	e := &env{in: obs.Input{Targets: targets, Discover: discover}, root: root}
	o := amp1(e, ck)
	if o.Result != obs.Absent || o.Proof == nil || o.Proof.Discovered["path_sudo"] != 0 || len(o.Proof.Targets) != 3 {
		t.Fatalf("want a verified absence over the three fixed paths, got %+v", o)
	}
	t.Setenv("PATH", t.TempDir()+":/usr/bin")
	os.WriteFile(filepath.Join(filepath.SplitList(os.Getenv("PATH"))[0], "sudo"), []byte("#!/bin/sh\n"), 0o755)
	if o := amp1(e, ck); o.Result != obs.Unknown {
		t.Fatalf("a sudo only elsewhere on PATH is recorded, never run, and unknown; got %+v", o)
	}
}

// PATH is split as execvp splits it (SBX-2): all of an empty PATH, "::" and a trailing colon are empty entries, each the
// working directory; an unset PATH leaves the search to the agent's launcher, which the probe can't tell. With a
// writable working directory holding a file named sudo, PER-2 and AMP-1 each find or are unknown, never a pass or
// absent.
func TestPATHWorkingDirectory(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sudo"); err == nil {
		t.Skip("sudo is installed here")
	}
	per2, _ := catalog.Get("PER-2")
	ck, _ := catalog.Get("AMP-1")
	targets, discover := catalog.Plan([]string{"AMP-1"})
	for path, why := range map[string]string{"": "only off the fixed paths", "::": "only off the fixed paths",
		"/nonexistent:": "only off the fixed paths", "unset": "PATH is unset"} {
		dir := t.TempDir()
		chdir(t, dir)
		os.WriteFile(filepath.Join(dir, "sudo"), []byte("#!/bin/sh\n"), 0o755) // only ever lstat'd
		t.Setenv("PATH", path)
		if path == "unset" {
			os.Unsetenv("PATH")
		}
		o := writable(testEnv(t, map[string][]string{"PER-2": {"/usr/local/bin"}}), per2)
		if o.Result != obs.Finding && o.Result != obs.Unknown {
			t.Errorf("PER-2, PATH %q, a writable working directory: want a finding or unknown, got %s", path, o.Result)
		}
		a := amp1(&env{in: obs.Input{Targets: targets, Discover: discover}, root: root}, ck)
		if a.Result != obs.Unknown || !strings.Contains(a.Reason, why) {
			t.Errorf("AMP-1, PATH %q, a sudo in the working directory: want unknown saying %q, got %s %q", path, why,
				a.Result, a.Reason)
		}
		t.Logf("PATH %q: PER-2 %s %s%s; AMP-1 %s %s", path, o.Result, o.Evidence, o.Reason, a.Result, a.Reason)
	}
}

// AMP-7 contacts only the API the plan named, never a local one.
func TestAMP7Gate(t *testing.T) {
	ck, _ := catalog.Get("AMP-7")
	e := &env{}
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	if o := amp7(e, ck); o.Result != obs.NotFound {
		t.Errorf("no API named: want not_found, got %+v", o)
	}
	t.Setenv("KUBERNETES_SERVICE_HOST", "192.0.2.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "6443")
	if o := amp7(e, ck); o.Result != obs.Unknown {
		t.Errorf("an API the plan didn't name: want unknown, got %+v", o)
	}
	t.Setenv("KUBERNETES_SERVICE_HOST", "127.0.0.1")
	e.in.KubeAPI = "127.0.0.1:6443"
	if o := amp7(e, ck); o.Result != obs.Unknown {
		t.Errorf("a local API: want unknown and never contacted, got %+v", o)
	}
}

func TestListing(t *testing.T) {
	if n, ok := listing("role-a\nrole-b\n"); !ok || len(n) != 2 {
		t.Errorf("AWS listing: %v %v", n, ok)
	}
	if n, ok := listing("default/\nsa@project.iam.gserviceaccount.com/\n"); !ok || len(n) != 2 || n[0] != "default" {
		t.Errorf("GCP listing: %v %v", n, ok)
	}
	if _, ok := listing("<html>not a listing</html>"); ok {
		t.Error("an HTML page isn't a listing")
	}
}

// A metadata address that is local to the box is never contacted (SBX-1): something the probe didn't start listens there.
func TestMetaNeverLocal(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan bool, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			c.Close()
			got <- true
		}
	}()
	if _, err := metaRequest(ln.Addr().String(), "GET", "/", "x", nil, time.Now().Add(time.Second)); err != errNoConnect {
		t.Fatalf("want errNoConnect, got %v", err)
	}
	if err := metaDial(ln.Addr().String(), time.Now().Add(time.Second)); err != errNoConnect {
		t.Fatalf("want errNoConnect from the dial, got %v", err)
	}
	select {
	case <-got:
		t.Fatal("the probe connected to a local listener")
	case <-time.After(200 * time.Millisecond):
	}
}

// A request whose line or headers carry a control character is never sent, whatever the address.
func TestMetaRequestUnsafe(t *testing.T) {
	for _, h := range []map[string]string{{"X-aws-ec2-metadata-token": "a\r\nX-Evil: 1"}, {"X\nY": "v"}} {
		if _, err := metaRequest("192.0.2.1:80", "GET", "/", "x", h, time.Now().Add(time.Second)); err != errUnsafeRequest {
			t.Errorf("%q: want errUnsafeRequest, got %v", h, err)
		}
	}
}

// An answer is read whole or not at all: a body cut short by a stall, a close, a cap or its own Content-Length is an
// error, never a shorter listing.
func TestReadAnswer(t *testing.T) {
	read := func(answer string, stall bool) (metaAnswer, error) {
		c, s := net.Pipe()
		defer c.Close()
		go func() {
			io.WriteString(s, answer)
			if stall {
				time.Sleep(time.Second)
			}
			s.Close()
		}()
		c.SetDeadline(time.Now().Add(200 * time.Millisecond))
		return readAnswer(c)
	}
	if a, err := read("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nrole-a\nrb\n", false); err != nil || a.body != "role-a\nrb\n" {
		t.Errorf("a whole answer: %+v %v", a, err)
	}
	if a, err := read("HTTP/1.1 200 OK\r\n\r\nrole-a\n", false); err != nil || a.body != "role-a\n" {
		t.Errorf("a whole answer ended by the close: %+v %v", a, err)
	}
	for name, tc := range map[string]struct {
		answer string
		stall  bool
	}{
		"a partial name, then a stall":  {"HTTP/1.1 200 OK\r\n\r\nrole-a\nro", true},
		"a short Content-Length body":   {"HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\nrole-a\n", false},
		"a body over the cap":           {"HTTP/1.1 200 OK\r\n\r\n" + strings.Repeat("role-a\n", 1000), false},
		"a Content-Length over the cap": {"HTTP/1.1 200 OK\r\nContent-Length: 9223372036854775807\r\n\r\n", false},
		"long headers, then a body past the read limit": {"HTTP/1.1 200 OK\r\nX-Pad: " + strings.Repeat("p", 17000) + "\r\n\r\n" +
			strings.Repeat("role-a\n", 600), false},
		"a chunked answer":                  {"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n7\r\nrole-a\n\r\n0\r\n\r\n", false},
		"headers that stall before the end": {"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n", true},
	} {
		if a, err := read(tc.answer, tc.stall); err == nil {
			t.Errorf("%s: want an error, got %+v", name, a)
		}
	}
}

// A request that gets no status line before the check's deadline cut the check short: errOutOfTime, never an ordinary
// no-answer that would let SEC-4 end not_found. Before the deadline, the same silence is errNoAnswer.
func TestExchangeDeadline(t *testing.T) {
	silent := func(attempt time.Duration, deadline time.Time) error {
		c, s := net.Pipe()
		defer c.Close()
		defer s.Close()
		go io.Copy(io.Discard, s) // reads the request, never answers
		c.SetDeadline(time.Now().Add(attempt))
		_, err := exchange(c, "GET / HTTP/1.1\r\n\r\n", deadline)
		return err
	}
	if err := silent(100*time.Millisecond, time.Now().Add(100*time.Millisecond)); err != errOutOfTime {
		t.Errorf("silent until the check's deadline: want errOutOfTime, got %v", err)
	}
	if err := silent(100*time.Millisecond, time.Now().Add(5*time.Second)); err != errNoAnswer {
		t.Errorf("silent for one attempt, well before the deadline: want errNoAnswer, got %v", err)
	}
}

// AMP-1's allow-list refuses the post-merge review's shape too: a link on sudo's chain the agent owns, in root's sticky
// /tmp, which it could replace; every link must be root's, and no directory on the way writable by anyone.
func TestPinSudoStickyLink(t *testing.T) {
	link := filepath.Join("/tmp", fmt.Sprintf("sp-sudolink-%d", os.Getpid()))
	os.Remove(link)
	if err := os.Symlink("/usr/bin", link); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(link) })
	fd, chain, why := pinSudo(filepath.Join(link, "su"))
	if why == "" {
		syscall.Close(fd)
		t.Fatalf("a chain through a link in a sticky directory: want refused, got pinned as %s", chain)
	}
	if !root && !strings.Contains(why, "isn't root's") && !strings.Contains(why, "/tmp is writable by anyone") { // root writes /usr/bin first
		t.Errorf("want the refusal to name the link or /tmp, got %q", why)
	}
}
