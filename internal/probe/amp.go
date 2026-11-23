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

	"sandprobe/internal/catalog"
	"sandprobe/internal/obs"
)

var checkLimit = 10 * time.Second // SBX-7: 10 s per check; a variable so tests can shorten it

// AMP-1: `sudo -n -l`, which lists policy and runs no command (SBX-1 (c)), from a sudo at one of the fixed paths: a
// regular, root-owned, setuid file there, or the one a symlink chain from there ends at (as Debian's alternatives and
// sudo-rs install it), which the agent can neither write nor replace, nor replace any link of the chain. The file is
// pinned with O_PATH, checked on that descriptor, and executed through it, so the inode checked is the inode that
// runs. A sudo anywhere else, or one that fails the check, is recorded and never run, and the reason says what failed.
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
	var refused []string
	for _, p := range present {
		fd, chain, why := pinSudo(p)
		if why != "" {
			refused = append(refused, p+": "+why)
			continue
		}
		return sudoList(chain, fd)
	}
	if len(present) == 0 {
		return unknownObs("sudo is only off the fixed paths (" + strings.Join(elsewhere, ", ") + "): recorded, never run")
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

// pinSudo follows p's symlink chain hop by hop to the file it ends at (SBX-2) and checks the chain: no link or file in
// it the agent can replace through a directory it can write, as each hop's path names its directories or as the real
// directories behind them are; and a file the agent can't write. The file is pinned with O_PATH and O_NOFOLLOW and
// checked on that descriptor: the inode the chain ended at, the inode the kernel reaches from p, and a regular,
// root-owned, setuid file. It returns the descriptor and the chain as a report shows it, or why p can't be trusted.
func pinSudo(p string) (fd int, chain, why string) {
	n, err := resolve(p)
	switch {
	case err != nil:
		return -1, "", "its links can't be followed to a file (" + err.Error() + ")"
	case n.errno != 0:
		return -1, "", "can't be checked: " + errName(n.errno)
	case n.st.Mode&syscall.S_IFMT != syscall.S_IFREG:
		return -1, "", n.final + " isn't a regular file"
	}
	for _, h := range n.hops {
		real, err := filepath.EvalSymlinks(filepath.Dir(h))
		if err != nil {
			return -1, "", "the directories of " + h + " can't be followed (" + err.Error() + ")"
		}
		for _, q := range []string{h, filepath.Join(real, filepath.Base(h))} {
			if dir := replacer(q); dir != "" {
				return -1, "", "the agent can write " + dir + ", so it could replace " + q
			}
		}
	}
	switch err := syscall.Faccessat(unixAtFDCWD, n.final, 2 /* W_OK */, atEAccess); errnoOf(err) {
	case syscall.EACCES, syscall.EROFS:
	case 0:
		return -1, "", "the agent can write " + n.final + " itself"
	default:
		return -1, "", "whether the agent can write " + n.final + " can't be told (" + err.Error() + ")"
	}
	fd, err = syscall.Open(n.final, unixOPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", n.final + " can't be pinned (" + err.Error() + ")"
	}
	var fst, kst syscall.Stat_t
	switch {
	case syscall.Fstat(fd, &fst) != nil:
		why = n.final + " can't be checked on its descriptor"
	case fst.Dev != n.st.Dev || fst.Ino != n.st.Ino:
		why = n.final + " changed between the check and the pin"
	case syscall.Stat(p, &kst) != nil || kst.Dev != fst.Dev || kst.Ino != fst.Ino:
		why = "the kernel doesn't reach " + n.final + " from " + p
	case fst.Mode&syscall.S_IFMT != syscall.S_IFREG:
		why = n.final + " isn't a regular file"
	case fst.Uid != 0:
		why = fmt.Sprintf("%s is owned by uid %d, not root", n.final, fst.Uid)
	case fst.Mode&syscall.S_ISUID == 0:
		why = n.final + " isn't setuid"
	}
	if why != "" {
		syscall.Close(fd)
		return -1, "", why
	}
	return fd, strings.Join(n.hops, " -> "), ""
}

const unixOPath = 0x200000 // O_PATH

var sudoTag = regexp.MustCompile(`^[A-Z_]+:\s*`)

// sudoList runs `sudo -n -l` through the pinned descriptor (as fexecve does), with an empty stdin and a fixed
// environment, and classifies what it lists, line by line as it arrives. Only the classification leaves: a rule's
// commands can carry arguments, and an argument can be a secret (SBX-2). The whole run, output and exit, is bounded by
// checkLimit (SBX-7): past it sudo is killed and reaped, and AMP-1 is unknown. A NOPASSWD rule is the finding.
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
	proc, err := os.StartProcess("/proc/self/fd/3", []string{"sudo", "-n", "-l"}, &os.ProcAttr{
		Env: []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}, Files: []*os.File{ir, ow, ow, pinned},
		Sys: &syscall.SysProcAttr{Setpgid: true}}) // its own group, so a timeout ends anything it started too
	ow.Close()
	if err != nil {
		return unknownObs("can't run " + p + " through its pinned descriptor: " + err.Error())
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
