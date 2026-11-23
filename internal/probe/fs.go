//go:build linux

package probe

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"sandprobe/internal/catalog"
	"sandprobe/internal/obs"
)

const (
	atEAccess = 0x200 // AT_EACCESS: check with the effective IDs, as the agent's own calls are
	maxHops   = 8     // SBX-2: at most 8 symlink hops
)

// errUnknowable means a target can't be judged at all (a symlink loop, a dangling link, a FIFO where a file should
// be). It makes the whole check unknown, never absent or a pass.
var errUnknowable = errors.New("unknowable")

// errDangling is a symlink chain ending nowhere: unknowable as a target, but a directory walk can skip it, since it
// leads to nothing the agent could read.
var errDangling = fmt.Errorf("%w (dangling symlink)", errUnknowable)

// lstat is syscall.Lstat, swappable so tests can inject a fault where only ENOENT may mean absence.
var lstat = syscall.Lstat

func unknowable(format string, a ...any) error {
	return fmt.Errorf("%w: %s", errUnknowable, fmt.Sprintf(format, a...))
}

func errnoOf(err error) syscall.Errno {
	var e syscall.Errno
	if errors.As(err, &e) {
		return e
	}
	return 0
}

var errnoNames = map[syscall.Errno]string{syscall.EACCES: "EACCES", syscall.EPERM: "EPERM", syscall.EROFS: "EROFS",
	syscall.ENOENT: "ENOENT", syscall.ENOTDIR: "ENOTDIR", syscall.ESRCH: "ESRCH"}

func errName(e syscall.Errno) string {
	if n, ok := errnoNames[e]; ok {
		return n
	}
	return fmt.Sprintf("errno %d", int(e))
}

// node is a path resolved hop by hop (SBX-2): every path visited, the final one, and how lstat answered for it.
type node struct {
	hops  []string
	final string
	st    syscall.Stat_t
	errno syscall.Errno // 0 when the final path exists
}

func resolve(path string) (node, error) {
	n := node{}
	p := path
	for i := 0; i <= maxHops; i++ {
		n.hops = append(n.hops, p)
		var st syscall.Stat_t
		if err := syscall.Lstat(p, &st); err != nil {
			switch e := errnoOf(err); e {
			case syscall.ENOENT, syscall.ENOTDIR, syscall.EACCES:
				if e != syscall.EACCES && len(n.hops) > 1 {
					return n, fmt.Errorf("%w: %s", errDangling, path)
				}
				n.final, n.errno = p, e
				return n, nil
			default:
				return n, err
			}
		}
		if st.Mode&syscall.S_IFMT != syscall.S_IFLNK {
			n.final, n.st = p, st
			return n, nil
		}
		t, err := os.Readlink(p)
		if err != nil {
			return n, err
		}
		if !filepath.IsAbs(t) {
			t = filepath.Join(filepath.Dir(p), t)
		}
		p = filepath.Clean(t)
	}
	return n, unknowable("%s has more than %d symlink hops", path, maxHops)
}

// searchable is TWN-2's second half: the deepest existing ancestor of p is searchable by the probe.
func searchable(p string) bool {
	for dir := filepath.Dir(p); ; dir = filepath.Dir(dir) {
		var st syscall.Stat_t
		if syscall.Stat(dir, &st) == nil {
			return syscall.Faccessat(unixAtFDCWD, dir, 1 /* X_OK */, atEAccess) == nil
		}
		if dir == "/" {
			return false
		}
	}
}

const unixAtFDCWD = -100

func absentTarget(name string, n node) obs.Target {
	return obs.Target{Name: name, State: "absent", Errno: errName(n.errno), ParentSearchable: searchable(n.final)}
}

// sysReopen is readCheck's read-only reopen, a seam so a test can stand in for a filesystem that refuses O_NOATIME.
var sysReopen = syscall.Open

// readCheck is the file_read mechanism (SEC-3): the inode is pinned with O_PATH, which opens nothing for I/O, checked
// to be a regular file on that descriptor, and only then reopened read-only through /proc/self/fd and closed, unread.
// A path swapped for a FIFO after the pin can't change what's opened.
func readCheck(name, path string) (t obs.Target, nonEmpty bool, err error) {
	t = obs.Target{Name: name}
	n, err := resolve(path)
	if err != nil {
		return t, false, err
	}
	switch n.errno {
	case syscall.ENOENT, syscall.ENOTDIR:
		return absentTarget(name, n), false, nil
	case syscall.EACCES:
		t.State, t.Errno = "refused", "EACCES"
		return t, false, nil
	}
	if n.st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return t, false, unknowable("%s isn't a regular file", path)
	}
	fd, err := syscall.Open(n.final, unixOPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		if e := errnoOf(err); e == syscall.EACCES || e == syscall.EPERM {
			t.State, t.Errno = "refused", errName(e)
			return t, false, nil
		}
		return t, false, err
	}
	defer syscall.Close(fd)
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return t, false, err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return t, false, unknowable("%s was swapped for something that isn't a regular file", path)
	}
	t.Device, t.Inode = uint64(st.Dev), st.Ino // pinned O_PATH identity, even if read-open is refused
	flags := syscall.O_RDONLY | syscall.O_NONBLOCK | syscall.O_NOCTTY | syscall.O_CLOEXEC
	if int(st.Uid) == os.Geteuid() {
		flags |= syscall.O_NOATIME
	}
	proc := fmt.Sprintf("/proc/self/fd/%d", fd)
	rfd, err := sysReopen(proc, flags, 0)
	if errnoOf(err) == syscall.EPERM && flags&syscall.O_NOATIME != 0 {
		// The filesystem may refuse O_NOATIME itself (Docker Desktop's file sharing does), which says nothing about
		// the agent reading the file: ask once more without it, and only that answer counts (SBX-2, no false passes).
		rfd, err = sysReopen(proc, flags&^syscall.O_NOATIME, 0)
	}
	if err != nil {
		if e := errnoOf(err); e == syscall.EACCES || e == syscall.EPERM {
			t.State, t.Errno = "refused", errName(e)
			return t, false, nil
		}
		return t, false, err
	}
	var opened syscall.Stat_t
	ferr := syscall.Fstat(rfd, &opened)
	syscall.Close(rfd)
	if ferr != nil {
		return t, false, ferr
	}
	if opened.Dev != st.Dev || opened.Ino != st.Ino {
		return t, false, unknowable("file identity changed")
	}
	t.Device, t.Inode = uint64(opened.Dev), opened.Ino
	t.State = "found"
	return t, opened.Size > 0, nil // only this bit leaves; no size is ever emitted (SBX-2)
}

// writeCheck is the write_perm mechanism (PER-1 to PER-4, AMP-8 kernel settings), as sweep and the recheck take it.
func writeCheck(name, path string) (obs.Target, error) {
	t, _, err := writeHow(name, path)
	return t, err
}

// writeHow is the write_perm mechanism: the path is found if the agent can write it, or replace it, or any hop of its
// symlink chain, through a real directory on the way it can write; the kernel answers that, for the agent as it is.
// Failing that, it is found if a change of identity or mode could get the write (TWN-4's model, gain); how then says
// so. Nothing is ever opened for writing.
func writeHow(name, path string) (t obs.Target, how string, err error) {
	t = obs.Target{Name: name}
	n, err := resolve(path)
	if err != nil {
		return t, "", err
	}
	for _, h := range n.hops {
		dir, err := replacer(h)
		if err != nil {
			return t, "", err
		}
		if dir != "" {
			t.State = "found"
			return t, "", nil
		}
	}
	switch n.errno {
	case syscall.ENOENT, syscall.ENOTDIR:
		t = absentTarget(name, n)
	case syscall.EACCES:
		t.State, t.Errno = "refused", "EACCES"
	default:
		err = syscall.Faccessat(unixAtFDCWD, n.final, 2 /* W_OK */, atEAccess)
		switch e := errnoOf(err); {
		case err == nil:
			t.State = "found"
			return t, "", nil
		case e == syscall.EACCES || e == syscall.EROFS:
			t.State, t.Errno = "refused", errName(e)
		default:
			return t, "", err
		}
	}
	for _, h := range n.hops {
		why, err := gain(h, 2, false)
		if err != nil || why != "" {
			if err == nil {
				t = obs.Target{Name: name, State: "found"}
			}
			return t, why, err
		}
	}
	return t, "", nil
}

// gain asks TWN-4's model whether a change could get the agent want (2 write, 4 read) on p, which the kernel refused
// it as it is: how, when it can; an error the check makes unknown, when the model can't tell. follow: p's own link is
// followed (a read, or a socket), rather than judged as an entry to replace; onlyOpen: only opening it counts.
func gain(p string, want uint32, onlyOpen bool) (string, error) {
	v, how, err := modelGain(p, want == 4 || onlyOpen, want, onlyOpen)
	switch {
	case err != nil:
		return "", unknowable("%s: %v", p, err)
	case v == cantTell:
		return "", unknowable("%s", how)
	case v == can:
		return how, nil
	}
	return "", nil
}

// Capabilities that let the agent past a refusal whatever a path's mode is now (TWN-4), by bit.
const (
	capChown         = 1 << 0
	capDacOverride   = 1 << 1
	capDacReadSearch = 1 << 2
	capFowner        = 1 << 3
	capSetgid        = 1 << 6
	capSetuid        = 1 << 7
	capSysModule     = 1 << 16
	capSysPtrace     = 1 << 19
	capSysAdmin      = 1 << 21

	// ownerPowers change any file's mode or take it over, or pass the write check outright on a writable mount.
	ownerPowers = capChown | capFowner | capSetuid | capDacOverride
	// pastPermissions reach past file permissions altogether, as AMP-2's Critical capabilities do.
	pastPermissions = capSysAdmin | capSysModule | capSysPtrace
	// readPowers let the agent read a file whatever its mode now, or make it readable.
	readPowers = ownerPowers | capDacReadSearch | capSetgid | pastPermissions
	// procPowers let the agent past ptrace's rules for another process's files: by ptrace itself, by taking the
	// process's identity, or past permissions altogether.
	procPowers = capSysPtrace | capSetuid | capSetgid | pastPermissions
)

// agentCaps is the agent's permitted and effective capabilities (TWN-4), read with capget(2), never from /proc; a
// permitted one can be raised at will. A failed read assumes all of them, so no refusal counts on a guess. A variable so the
// tests can give the agent capabilities.
var agentCaps = func() uint64 {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if unix.Capget(&hdr, &data[0]) != nil {
		return ^uint64(0)
	}
	var caps uint64
	for i, d := range data {
		caps |= uint64(d.Effective|d.Permitted) << (32 * i)
	}
	return caps
}

// capList names the capabilities set in caps.
func capList(caps uint64) string { return strings.Join(catalog.CapList(caps), ", ") }

// replacer: some real directory on the way to p lets the agent as it is create, rename or remove p (or the directory
// leading to it): writable and searchable, by the kernel's own check; not protected by a sticky bit, which spares
// entries the agent doesn't own unless it holds CAP_FOWNER; not procfs or sysfs, where nothing is created; and not the
// parent of a mount point. Every link on the way is followed first, so each directory judged is the one the kernel
// traverses (TWN-4). It returns that directory, or "".
func replacer(p string) (string, error) {
	ns, err := pathNodes(p, false)
	if err != nil {
		return "", unknowable("%v", err)
	}
	euid := uint32(os.Geteuid())
	fowner := theAgent().eff&capFowner != 0
	for j := len(ns) - 2; j >= 0; j-- {
		d, c := ns[j], ns[j+1]
		if !d.seen || !d.exists || d.noEntries ||
			syscall.Faccessat(unixAtFDCWD, d.path, 3 /* W_OK|X_OK */, atEAccess) != nil {
			continue
		}
		if c.seen && c.exists && (c.mountPoint ||
			d.mode&syscall.S_ISVTX != 0 && !fowner && d.uid != euid && c.uid != euid) {
			continue
		}
		return d.path, nil
	}
	return "", nil
}

// pseudo: procfs and sysfs directories, where faccessat says root may write but nothing can be created, renamed or
// removed, so they never make a path replaceable. A file there is still judged by its own write check.
func pseudo(dir string) bool {
	var fs syscall.Statfs_t
	if syscall.Statfs(dir, &fs) != nil {
		return false
	}
	return fs.Type == 0x9fa0 /* PROC_SUPER_MAGIC */ || fs.Type == 0x62656572 /* SYSFS_MAGIC */
}

// socketCheck is AMP-4's use of write_perm: a control socket is found only if it exists as a socket and the agent
// has write permission on it, which is what connect needs, or could give itself that permission by a change of
// identity or mode (TWN-4's model; how then says so). Rebinding its path is no way to its server, so replacing doesn't
// count. A missing socket exposes nothing, however creatable its path; it must be verified absent. Something other than
// a socket at the path is unknown.
func socketCheck(name, path string) (t obs.Target, how string, err error) {
	t = obs.Target{Name: name}
	n, err := resolve(path)
	if err != nil {
		return t, "", err
	}
	switch n.errno {
	case syscall.ENOENT, syscall.ENOTDIR:
		return absentTarget(name, n), "", nil
	case syscall.EACCES:
		t.State, t.Errno = "refused", "EACCES"
	default:
		if n.st.Mode&syscall.S_IFMT != syscall.S_IFSOCK {
			return t, "", unknowable("%s exists but isn't a socket", path)
		}
		err = syscall.Faccessat(unixAtFDCWD, n.final, 2 /* W_OK */, atEAccess)
		switch e := errnoOf(err); {
		case err == nil:
			t.State = "found"
			return t, "", nil
		case e == syscall.EACCES || e == syscall.EROFS:
			t.State, t.Errno = "refused", errName(e)
		default:
			return t, "", err
		}
	}
	why, err := gain(path, 2, true)
	if err != nil || why != "" {
		if err == nil {
			t = obs.Target{Name: name, State: "found"}
		}
		return t, why, err
	}
	return t, "", nil
}

// permCheck is the read_perm mechanism (AMP-8 block devices): faccessat(R_OK), never opened.
func permCheck(name, path string) (obs.Target, error) {
	t := obs.Target{Name: name}
	err := syscall.Faccessat(unixAtFDCWD, path, 4 /* R_OK */, atEAccess)
	switch e := errnoOf(err); {
	case err == nil:
		t.State = "found"
	case e == syscall.EACCES || e == syscall.EPERM:
		t.State, t.Errno = "refused", errName(e)
	case e == syscall.ENOENT:
		t.State, t.Errno, t.ParentSearchable = "absent", "ENOENT", searchable(path)
	default:
		return t, err
	}
	return t, nil
}

// procCheck is the proc_open mechanism (SEC-2, SEC-5): open /proc/<pid>/<file> read-only, read nothing. The kernel
// decides access at open, so the open itself is the proof. A process that exited is absent.
func procCheck(name, path string) (obs.Target, error) {
	t := obs.Target{Name: name}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	switch e := errnoOf(err); {
	case err == nil:
		syscall.Close(fd)
		t.State = "found"
	case e == syscall.EACCES || e == syscall.EPERM:
		t.State, t.Errno = "refused", errName(e)
	case e == syscall.ENOENT || e == syscall.ESRCH:
		t.State, t.Errno, t.ParentSearchable = "absent", "ENOENT", true
	default:
		return t, err
	}
	return t, nil
}
