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
// symlink chain, through an ancestor directory it can write, or if it can make the path or such a directory writable
// whatever its mode now (TWN-4); how then says so. Nothing is ever opened for writing.
func writeHow(name, path string) (t obs.Target, how string, err error) {
	t = obs.Target{Name: name}
	n, err := resolve(path)
	if err != nil {
		return t, "", err
	}
	for _, h := range n.hops {
		if dir, why := replacer(h); dir != "" {
			t.State = "found"
			if why != "" {
				how = "it can make " + dir + " writable, as " + why
			}
			return t, how, nil
		}
	}
	switch n.errno {
	case syscall.ENOENT, syscall.ENOTDIR:
		return absentTarget(name, n), "", nil
	case syscall.EACCES:
		t.State, t.Errno = "refused", "EACCES"
		return t, "", nil
	}
	err = syscall.Faccessat(unixAtFDCWD, n.final, 2 /* W_OK */, atEAccess)
	switch e := errnoOf(err); {
	case err == nil:
		t.State = "found"
	case e == syscall.EACCES || e == syscall.EROFS:
		if why := ownerPower(n.final, &n.st); why != "" {
			t.State = "found"
			return t, "it can make " + n.final + " writable, as " + why, nil
		}
		t.State, t.Errno = "refused", errName(e)
	default:
		return t, "", err
	}
	return t, "", nil
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
func capList(caps uint64) string {
	var held []string
	for bit := 0; bit < 64; bit++ {
		if caps&(1<<bit) != 0 && bit < len(capNames) {
			held = append(held, "CAP_"+capNames[bit])
		} else if caps&(1<<bit) != 0 {
			held = append(held, fmt.Sprintf("capability %d", bit))
		}
	}
	return strings.Join(held, ", ")
}

// modeCanChange: path isn't on a read-only mount, nor in procfs or sysfs, where no mode can change. When the
// filesystem can't be told, it can (TWN-4).
func modeCanChange(path string) bool {
	var fs syscall.Statfs_t
	return syscall.Statfs(path, &fs) != nil ||
		fs.Flags&1 /* ST_RDONLY */ == 0 && fs.Type != 0x9fa0 /* PROC_SUPER_MAGIC */ && fs.Type != 0x62656572 /* SYSFS_MAGIC */
}

// ownerPower says why the agent could make path writable whatever its mode now, or "" (TWN-4): it owns it, holds an
// owner's power over any file, or holds CAP_SETGID where a group may write it; none of them where no mode can change.
func ownerPower(path string, st *syscall.Stat_t) string {
	if !modeCanChange(path) {
		return ""
	}
	caps := agentCaps()
	group := uint32(0o020) // a group may write the file, or write and search the directory
	if st.Mode&syscall.S_IFMT == syscall.S_IFDIR {
		group = 0o030
	}
	switch {
	case int(st.Uid) == os.Geteuid():
		return "it owns it"
	case caps&ownerPowers != 0:
		return "it holds " + capList(caps&ownerPowers)
	case caps&capSetgid != 0 && st.Mode&group == group:
		return "it holds CAP_SETGID and a group may write it"
	}
	return ""
}

// readPower says why the agent could read path, which refused it, whatever its mode now, or "" (TWN-4): it owns the
// file (where its mode can change), or a directory on the way that refuses it a search; owning a directory it can
// already search gives it no read of another's file in it.
func readPower(path string) string {
	euid := os.Geteuid()
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err == nil {
		if int(st.Uid) == euid && modeCanChange(path) {
			return "it owns " + path
		}
		return ""
	}
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		var ds syscall.Stat_t
		if syscall.Stat(dir, &ds) == nil && int(ds.Uid) == euid && modeCanChange(dir) &&
			syscall.Faccessat(unixAtFDCWD, dir, 1 /* X_OK */, atEAccess) != nil {
			return "it owns " + dir + ", which refuses it a search, and can change that"
		}
		if dir == "/" {
			return ""
		}
	}
}

// replacer: some ancestor directory of p lets the agent create, rename or remove p (or the directory leading to it):
// writable and searchable, or one it can make so (ownerPower); not protected by a sticky bit, which spares entries the
// agent doesn't own unless it holds an owner's power; and not the parent of a mount point. Mount points are told by a
// device change, which misses a bind mount of the same filesystem; that errs towards a finding, never a pass. It
// returns that directory, and why the agent can make it writable when it must first, or "" for none.
func replacer(p string) (dir, how string) {
	euid := os.Geteuid()
	powers := agentCaps()&(capChown|capFowner|capSetuid) != 0 // CAP_DAC_OVERRIDE doesn't pass a sticky bit
	child := p
	for dir := filepath.Dir(p); ; dir = filepath.Dir(dir) {
		var ds, cs syscall.Stat_t
		if !pseudo(dir) && syscall.Lstat(dir, &ds) == nil {
			how, ok := "", syscall.Faccessat(unixAtFDCWD, dir, 3 /* W_OK|X_OK */, atEAccess) == nil
			if !ok {
				how = ownerPower(dir, &ds)
				ok = how != ""
			}
			if ok {
				exists := syscall.Lstat(child, &cs) == nil
				mount := exists && cs.Dev != ds.Dev // a mount point can't be renamed or removed (EBUSY)
				if !mount && (!exists || !stickySpares(ds, cs, euid, powers)) {
					return dir, how
				}
			}
		}
		if dir == "/" {
			return "", ""
		}
		child = dir
	}
}

// stickySpares: a sticky directory dir keeps the agent from removing or renaming its existing entry child, which holds
// only while the agent owns neither and has no power over the entry (CAP_FOWNER passes the sticky bit outright;
// CAP_CHOWN and CAP_SETUID make the agent the entry's owner).
func stickySpares(dir, child syscall.Stat_t, euid int, powers bool) bool {
	return dir.Mode&syscall.S_ISVTX != 0 && !powers && int(dir.Uid) != euid && int(child.Uid) != euid
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
// has write permission on it, which is what connect needs, or can give itself that permission (ownerPower, TWN-4; how then
// says so). A missing socket exposes nothing, however creatable its path; it must be verified absent. Something other
// than a socket at the path is unknown, and so is one behind a directory the agent can't search but could make
// searchable.
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
		for dir := filepath.Dir(n.final); ; dir = filepath.Dir(dir) {
			var ds syscall.Stat_t
			if syscall.Lstat(dir, &ds) == nil {
				if why := ownerPower(dir, &ds); why != "" {
					return t, "", unknowable("%s is behind a directory the agent can't search, but it can make %s searchable, as %s", path, dir, why)
				}
			}
			if dir == "/" {
				break
			}
		}
		t.State, t.Errno = "refused", "EACCES"
		return t, "", nil
	}
	if n.st.Mode&syscall.S_IFMT != syscall.S_IFSOCK {
		return t, "", unknowable("%s exists but isn't a socket", path)
	}
	err = syscall.Faccessat(unixAtFDCWD, n.final, 2 /* W_OK */, atEAccess)
	switch e := errnoOf(err); {
	case err == nil:
		t.State = "found"
	case e == syscall.EACCES || e == syscall.EROFS:
		if why := ownerPower(n.final, &n.st); why != "" {
			t.State = "found"
			return t, "it can make " + n.final + " writable, as " + why, nil
		}
		t.State, t.Errno = "refused", errName(e)
	default:
		return t, "", err
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
