//go:build linux

package probe

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"sandprobe/internal/catalog"
	"sandprobe/internal/obs"
)

var checkLimit = 10 * time.Second // SBX-7: 10 s per check; a variable so tests can shorten it

// AMP-1: `sudo -n -l`, which lists policy and runs no command (SBX-1 (c)), from a sudo at one of the fixed paths: a
// regular, root-owned, setuid file there, or the one a symlink chain from there ends at (as Debian's alternatives and
// sudo-rs install it), trusted only by an allow-list of root's ownership along the whole chain, and only for an agent
// that isn't root and holds no capability. The file is pinned with O_PATH, checked on that descriptor, and executed
// from it, so the inode checked is the inode that runs. A sudo anywhere else, or one that fails the check, is recorded
// and never run, and the reason says what failed.
func amp1(e *env, ck *catalog.Check) obs.Observation {
	var ts []obs.Target
	var present []string
	for _, p := range e.in.Targets[ck.ID] {
		var st syscall.Stat_t
		switch err := lstat(p, &st); errnoOf(err) {
		case 0:
			present = append(present, p)
		case syscall.ENOENT, syscall.ENOTDIR:
			ts = append(ts, obs.Target{Name: p, State: "absent", Errno: "ENOENT", ParentSearchable: searchable(p)})
		default:
			return unknownObs(fmt.Sprintf("checking %s: %v", p, err))
		}
	}
	elsewhere, err := pathSudo(e.in.Targets[ck.ID])
	if err != nil {
		return unknownObs(err.Error())
	}
	if len(present) == 0 && len(elsewhere) == 0 {
		return obs.Observation{Result: obs.Absent, Proof: &obs.Proof{Mechanism: ck.Mechanism, Root: e.root,
			Discovered: map[string]int{"path_sudo": 0}, Targets: ts}}
	}
	if len(present) == 0 {
		return unknownObs("sudo is only off the fixed paths (" + strings.Join(elsewhere, ", ") + "): recorded, never run")
	}
	if why := privileged(); why != "" {
		return unknownObs("no sudo at a fixed path can be trusted to run, so none ran: " + why)
	}
	var refused []string
	for _, p := range present {
		fd, chain, why := pinSudo(p)
		if why != "" {
			refused = append(refused, p+": "+why)
			continue
		}
		return sudoList(chain, fd)
	}
	return unknownObs("no sudo at a fixed path can be trusted to run, so none ran: " + strings.Join(refused, "; "))
}

// pathSudo: sudo in any PATH directory other than the fixed ones. Only lstat; nothing found here ever runs.
func pathSudo(fixed []string) ([]string, error) {
	skip := map[string]bool{}
	for _, p := range fixed {
		skip[filepath.Dir(p)] = true
	}
	var out []string
	for _, d := range filepath.SplitList(os.Getenv("PATH")) {
		if !filepath.IsAbs(d) || skip[filepath.Clean(d)] {
			continue
		}
		skip[filepath.Clean(d)] = true
		p := filepath.Join(d, "sudo")
		var st syscall.Stat_t
		switch err := lstat(p, &st); errnoOf(err) {
		case 0:
			out = append(out, p)
		case syscall.ENOENT, syscall.ENOTDIR, syscall.EACCES: // missing, or in a directory the agent can't search
		default:
			return nil, fmt.Errorf("checking %s: %v", p, err)
		}
	}
	return out, nil
}

// pinSudo walks p to the file it names (walk) and trusts the chain only by AMP-1's allow-list: every link on it owned by
// root, and every directory on the real path to each link and to the file owned by root, not world-writable, and not
// writable by the agent (rootDir); the file a regular, root-owned, setuid file the agent can't write, named sudo or
// sudo.ws. The file is pinned with O_PATH and O_NOFOLLOW and checked on that descriptor: the inode the walk ended at,
// and the inode the kernel reaches from p. It returns the descriptor and the chain as a report shows it, or why p can't
// be trusted. It assumes an agent that isn't root and holds no capability (privileged).
func pinSudo(p string) (fd int, chain, why string) {
	links, steps, real, st, err := walk(p)
	switch {
	case err != nil && len(links) == 0:
		return -1, "", "can't be checked (" + err.Error() + ")"
	case err != nil:
		return -1, "", "its links can't be followed to a file (" + err.Error() + ")"
	}
	seen := map[string]bool{}
	for _, q := range append(links, real) {
		var ls syscall.Stat_t
		if q != real && (syscall.Lstat(q, &ls) != nil || ls.Uid != 0) {
			return -1, "", fmt.Sprintf("the link %s isn't root's (uid %d)", q, ls.Uid)
		}
		for d := filepath.Dir(q); !seen[d]; d = filepath.Dir(d) {
			seen[d] = true
			if why := rootDir(d); why != "" {
				return -1, "", why
			}
		}
	}
	switch {
	case st.Mode&syscall.S_IFMT != syscall.S_IFREG:
		return -1, "", real + " isn't a regular file"
	}
	switch err := syscall.Faccessat(unixAtFDCWD, real, 2 /* W_OK */, atEAccess); errnoOf(err) {
	case syscall.EACCES, syscall.EROFS:
	case 0:
		return -1, "", "the agent can write " + real + " itself"
	default:
		return -1, "", "whether the agent can write " + real + " can't be told (" + err.Error() + ")"
	}
	fd, err = syscall.Open(real, unixOPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", real + " can't be pinned (" + err.Error() + ")"
	}
	var fst, kst syscall.Stat_t
	switch {
	case syscall.Fstat(fd, &fst) != nil:
		why = real + " can't be checked on its descriptor"
	case fst.Dev != st.Dev || fst.Ino != st.Ino:
		why = real + " changed between the check and the pin"
	case syscall.Stat(p, &kst) != nil || kst.Dev != fst.Dev || kst.Ino != fst.Ino:
		why = "the kernel doesn't reach " + real + " from " + p
	case fst.Mode&syscall.S_IFMT != syscall.S_IFREG:
		why = real + " isn't a regular file"
	case fst.Uid != 0:
		why = fmt.Sprintf("%s is owned by uid %d, not root", real, fst.Uid)
	case fst.Mode&syscall.S_ISUID == 0:
		why = real + " isn't setuid"
	case !sudoNames[filepath.Base(real)]:
		why = real + " isn't named sudo or sudo.ws, so it isn't run as one"
	}
	if why != "" {
		syscall.Close(fd)
		return -1, "", why
	}
	return fd, strings.Join(steps, " -> "), ""
}

// sudoNames are the files a sudo chain may end at: sudo itself (sudo-rs's included) and Debian's sudo.ws.
var sudoNames = map[string]bool{"sudo": true, "sudo.ws": true}

// rootDir says why a directory on sudo's chain fails AMP-1's allow-list, or "": owned by root (an owner can make its
// own directory writable at any time, whatever its mode now), not world-writable, sticky or not, and not writable by
// the agent.
func rootDir(d string) string {
	var st syscall.Stat_t
	switch {
	case syscall.Lstat(d, &st) != nil:
		return "the directory " + d + " can't be checked"
	case st.Uid != 0:
		return fmt.Sprintf("%s is owned by uid %d, not root", d, st.Uid)
	case st.Mode&0o002 != 0:
		return d + " is writable by anyone"
	}
	switch err := syscall.Faccessat(unixAtFDCWD, d, 2 /* W_OK */, atEAccess); errnoOf(err) {
	case syscall.EACCES, syscall.EROFS:
		return ""
	case 0:
		return "the agent can write " + d
	default:
		return "whether the agent can write " + d + " can't be told (" + err.Error() + ")"
	}
}

// walk follows p one path component at a time (AMP-1): every symlink on the way, a directory's as well as the last
// name's, counts against SBX-2's eight hops. It returns each link it followed (a path with no link in it), the whole
// path after each one, starting with p, as a report shows the chain, and the link-free path it ends at with lstat's
// answer for it. ".." is taken against that link-free path, as the kernel takes it.
func walk(p string) (links, steps []string, real string, st syscall.Stat_t, err error) {
	steps = []string{p}
	rest := strings.Split(p, "/")
	cur := "/"
	for len(rest) > 0 {
		c := rest[0]
		rest = rest[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			cur = filepath.Dir(cur)
			continue
		}
		next := filepath.Join(cur, c)
		if err := syscall.Lstat(next, &st); err != nil {
			return links, steps, "", st, fmt.Errorf("%s: %s", next, errName(errnoOf(err)))
		}
		if st.Mode&syscall.S_IFMT != syscall.S_IFLNK {
			cur = next
			continue
		}
		if len(links) == maxHops {
			return links, steps, "", st, fmt.Errorf("more than %d links on the way", maxHops)
		}
		t, err := os.Readlink(next)
		if err != nil {
			return links, steps, "", st, fmt.Errorf("%s: %s", next, errName(errnoOf(err)))
		}
		links = append(links, next)
		if filepath.IsAbs(t) {
			cur = "/"
		}
		steps = append(steps, filepath.Join(append([]string{cur, t}, rest...)...))
		rest = append(strings.Split(t, "/"), rest...)
	}
	if err := syscall.Lstat(cur, &st); err != nil {
		return links, steps, "", st, fmt.Errorf("%s: %s", cur, errName(errnoOf(err)))
	}
	return links, steps, cur, st, nil
}

// privileged says why no sudo chain can be trusted to this agent, or "": AMP-1's allow-list binds only an agent that
// isn't root and holds no capability, permitted, effective or inheritable. It reads them with geteuid(2) and capget(2),
// never from /proc, and fails closed.
func privileged() string {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return "the agent's capabilities can't be read (" + err.Error() + ")"
	}
	var caps uint64
	for i, d := range data {
		caps |= uint64(d.Effective|d.Permitted|d.Inheritable) << (32 * i)
	}
	return privilegedWhy(syscall.Geteuid(), caps)
}

func privilegedWhy(euid int, caps uint64) string {
	var held []string
	for bit := 0; bit < 64; bit++ {
		if caps&(1<<bit) == 0 {
			continue
		}
		if bit < len(capNames) {
			held = append(held, "CAP_"+capNames[bit])
		} else {
			held = append(held, fmt.Sprintf("capability %d", bit))
		}
	}
	if n := len(held); n > 8 {
		held = append(held[:8], fmt.Sprintf("%d more", n-8))
	}
	who := ""
	switch {
	case euid == 0 && len(held) > 0:
		who = "the agent is root and holds " + strings.Join(held, ", ")
	case euid == 0:
		who = "the agent is root"
	case len(held) > 0:
		who = "the agent holds " + strings.Join(held, ", ")
	default:
		return ""
	}
	return who + ", so it could have replaced, exchanged or re-owned a link or directory on sudo's chain and left it " +
		"looking like root's; ownership and permissions can't show the chain is out of its reach"
}

// capNames are the capabilities by bit (linux/capability.h).
var capNames = []string{"CHOWN", "DAC_OVERRIDE", "DAC_READ_SEARCH", "FOWNER", "FSETID", "KILL", "SETGID", "SETUID",
	"SETPCAP", "LINUX_IMMUTABLE", "NET_BIND_SERVICE", "NET_BROADCAST", "NET_ADMIN", "NET_RAW", "IPC_LOCK", "IPC_OWNER",
	"SYS_MODULE", "SYS_RAWIO", "SYS_CHROOT", "SYS_PTRACE", "SYS_PACCT", "SYS_ADMIN", "SYS_BOOT", "SYS_NICE",
	"SYS_RESOURCE", "SYS_TIME", "SYS_TTY_CONFIG", "MKNOD", "LEASE", "AUDIT_WRITE", "AUDIT_CONTROL", "SETFCAP",
	"MAC_OVERRIDE", "MAC_ADMIN", "SYSLOG", "WAKE_ALARM", "BLOCK_SUSPEND", "AUDIT_READ", "PERFMON", "BPF",
	"CHECKPOINT_RESTORE"}

const unixOPath = 0x200000 // O_PATH

var sudoTag = regexp.MustCompile(`^[A-Z_]+:\s*`)

// sudoEnv is sudo's whole environment; a variable only so the tests' stand-ins can be told what to play.
var sudoEnv = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}

// sudoList runs `sudo -n -l` from the pinned descriptor itself, by execveat (spawnFD), never by a path, with an empty
// stdin and a fixed environment, and classifies what it lists, line by line as it arrives. Only the classification
// leaves: a rule's commands can carry arguments, and an argument can be a secret (SBX-2). The whole run, output and
// exit, is bounded by checkLimit (SBX-7): past it sudo is killed and reaped, and AMP-1 is unknown. A NOPASSWD rule is
// the finding; a run ended by a signal is unknown, since a child that died before its exec looks the same.
func sudoList(p string, fd int) obs.Observation {
	pinned := os.NewFile(uintptr(fd), p)
	defer pinned.Close()
	ir, iw, err := os.Pipe()
	if err != nil {
		return unknownObs("can't start sudo: " + err.Error())
	}
	iw.Close()
	defer ir.Close()
	or, ow, err := os.Pipe()
	if err != nil {
		return unknownObs("can't start sudo: " + err.Error())
	}
	defer or.Close()
	// its own process group, so a timeout ends anything it started too
	pid, err := spawnFD(int(pinned.Fd()), []string{"sudo", "-n", "-l"}, sudoEnv, [3]int{int(ir.Fd()), int(ow.Fd()), int(ow.Fd())})
	ow.Close()
	if err != nil {
		return unknownObs("can't run " + p + " from its pinned descriptor: " + err.Error())
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		syscall.Kill(-pid, syscall.SIGKILL)
		return unknownObs("can't follow the sudo it started: " + err.Error())
	}
	type tally struct {
		rules int
		all   bool
		err   error
	}
	read := make(chan tally, 1)
	go func() { // drains everything, so sudo never blocks on a full pipe; keeps only the counts
		var t tally
		sc := bufio.NewScanner(or)
		for sc.Scan() {
			if all, ok := sudoRule(sc.Text()); ok {
				t.rules++
				t.all = t.all || all
			}
		}
		if t.err = sc.Err(); t.err != nil {
			io.Copy(io.Discard, or)
		}
		read <- t
	}()
	exited := make(chan *os.ProcessState, 1)
	go func() { st, _ := proc.Wait(); exited <- st }()
	limit := time.NewTimer(checkLimit)
	defer limit.Stop()
	var st *os.ProcessState
	select {
	case st = <-exited:
	case <-limit.C:
		syscall.Kill(-proc.Pid, syscall.SIGKILL)
		<-exited
		or.Close()
		return unknownObs("sudo -n -l didn't finish in time")
	}
	var t tally
	select { // sudo has exited; anything it left holding the pipe is cut off by the same limit
	case t = <-read:
	case <-limit.C:
		syscall.Kill(-proc.Pid, syscall.SIGKILL)
		or.Close()
		return unknownObs("sudo -n -l's output didn't end in time")
	}
	switch {
	case st == nil:
		return unknownObs("sudo -n -l: no exit status")
	case st.Sys().(syscall.WaitStatus).Signaled():
		return unknownObs("sudo -n -l ended by a signal, " + st.Sys().(syscall.WaitStatus).Signal().String())
	case t.err != nil:
		return unknownObs("sudo -n -l's listing didn't read as lines: " + t.err.Error())
	case t.rules == 0:
		return obs.Observation{Result: obs.NotFound, Reason: fmt.Sprintf("sudo -n -l, run from %s, listed no NOPASSWD rule (exit %d); "+
			"a site's listpw setting can hide one, so this isn't proven", p, st.ExitCode())}
	}
	v, what := "nopasswd_named", "for named commands only"
	if t.all {
		v, what = "nopasswd_all", "one of them for every command"
	}
	return obs.Observation{Result: obs.Finding, Variant: v, Evidence: fmt.Sprintf("sudo -n -l, run from %s (root-owned, "+
		"setuid, out of the agent's reach), lists %d NOPASSWD rule(s), %s; the commands aren't recorded", p, t.rules, what)}
}

// sudoRule classifies one line of sudo's listing: whether it is a NOPASSWD rule, and whether it allows every command.
func sudoRule(line string) (all, ok bool) {
	_, cmds, ok := strings.Cut(line, "NOPASSWD:")
	if !ok {
		return false, false
	}
	cmds = strings.TrimSpace(cmds)
	for sudoTag.MatchString(cmds) { // further tags, such as SETENV:
		cmds = sudoTag.ReplaceAllString(cmds, "")
	}
	for _, c := range strings.Split(cmds, ",") {
		if strings.TrimSpace(c) == "ALL" {
			return true, true
		}
	}
	return false, true
}

// AMP-6: vsock to the host. The port list to try on CID 2 isn't set yet (SPEC, AMP-6), so with a device present the
// check can't say anything; without one, the host skips it (GRD-3).
func amp6(e *env, ck *catalog.Check) obs.Observation {
	if !vsockDevice() {
		return obs.Observation{Result: obs.NotFound, Reason: "no vsock device"}
	}
	return unknownObs("/dev/vsock is present, but the host ports to try on CID 2 aren't set yet, so nothing was connected")
}

func vsockDevice() bool {
	var st syscall.Stat_t
	return syscall.Lstat("/dev/vsock", &st) == nil && st.Mode&syscall.S_IFMT == syscall.S_IFCHR
}

// kubeAPI is the Kubernetes API the agent's environment names, as "ip:port".
func kubeAPI() (string, bool) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	if host == "" {
		return "", false
	}
	port := os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS")
	if port == "" {
		port = os.Getenv("KUBERNETES_SERVICE_PORT")
	}
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(host, port), true
}

// AMP-7: a TCP connect and a TLS handshake to the Kubernetes API the plan named, sending no request. A local address
// is never contacted (SBX-1). Find-only: not reaching it proves nothing.
func amp7(e *env, ck *catalog.Check) obs.Observation {
	api, set := kubeAPI()
	switch {
	case !set:
		return obs.Observation{Result: obs.NotFound, Reason: "the agent's environment names no Kubernetes API"}
	case e.in.KubeAPI == "" || api != e.in.KubeAPI:
		return unknownObs("the agent's Kubernetes API isn't the one the plan named, so it isn't contacted (SBX-3)")
	}
	host, _, _ := net.SplitHostPort(api)
	ip := net.ParseIP(host)
	switch {
	case ip == nil:
		return unknownObs("KUBERNETES_SERVICE_HOST isn't an IP address")
	case isLocal(ip):
		return unknownObs("the Kubernetes API is at a local address, which the probe never contacts (SBX-1)")
	}
	conn, err := net.DialTimeout("tcp", api, attemptTimeout)
	if err != nil {
		return obs.Observation{Result: obs.NotFound, Reason: "no TCP connection to the Kubernetes API at " + api}
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(attemptTimeout))
	tc := tls.Client(conn, &tls.Config{ServerName: "kubernetes.default.svc", InsecureSkipVerify: true})
	if err := tc.Handshake(); err != nil {
		return obs.Observation{Result: obs.NotFound, Reason: "TCP reached " + api + ", but no TLS handshake completed"}
	}
	return obs.Observation{Result: obs.Finding, Variant: "k8s_api",
		Evidence: "a TLS handshake completed with the Kubernetes API at " + api + " (no request sent)"}
}
