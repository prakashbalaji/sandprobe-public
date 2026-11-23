//go:build linux

package probe

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// pathWalk is a path resolved as the kernel resolves it (SBX-2, TWN-4): one component at a time, on directory
// descriptors. Each entry is opened O_PATH|O_NOFOLLOW in the real directory the walk has reached; a symlink is read with
// readlinkat and its target's components pushed onto what is left of the path, an absolute target resolved from "/",
// a relative one from the directory holding the link; ".." is opened by the kernel, so it moves physically. One budget
// of eight links covers the whole path, a directory's links and the last name's alike. Every lookup is kept as a node,
// symlink entries included, each with the directory it was looked up in; the descriptors stay open until close, so the
// checks act on the very inodes the walk judged. Nothing is read or written.
type pathWalk struct {
	nodes    []inode
	fds      []int         // an O_PATH descriptor per node; -1 where it doesn't exist or can't be seen
	names    []string      // the name each node was looked up by in its directory
	steps    []string      // the path as each followed link leaves it, starting with the path itself, for reports
	errno    syscall.Errno // why the walk stopped short: ENOENT or ENOTDIR (missing), EACCES (can't search); 0 at the end
	dangling bool          // it stopped short following the last name's own link: a chain ending nowhere
}

func (w *pathWalk) close() {
	for _, fd := range w.fds {
		if fd >= 0 {
			syscall.Close(fd)
		}
	}
}

func (w *pathWalk) last() int { return len(w.nodes) - 1 }

// walkPath resolves p (made absolute against the working directory) as the kernel does. follow: the last name's own
// link is followed too. Past eight links, or where the kernel's ".." isn't the directory the walk looked it up in, the
// path can't be judged: an unknowable error. The caller closes the walk.
func walkPath(p string, follow bool) (*pathWalk, error) {
	if !filepath.IsAbs(p) {
		wd, err := os.Getwd()
		if err != nil {
			return nil, unknowable("%s is relative and the working directory can't be told", p)
		}
		p = filepath.Join(wd, p)
	}
	root, err := syscall.Open("/", unixOPath|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, unknowable("/ can't be opened: %v", err)
	}
	w := &pathWalk{steps: []string{p}}
	n, err := describeFD(root, "/")
	if err != nil {
		syscall.Close(root)
		return nil, err
	}
	n.parent = -1
	w.add(n, root, "/")
	rest := strings.Split(p, "/")
	cur, hops, final := 0, 0, false
	for len(rest) > 0 {
		c := rest[0]
		rest = rest[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			if err := w.up(&cur); err != nil {
				w.close()
				return nil, err
			}
			continue
		}
		last := true
		for _, r := range rest {
			last = last && (r == "" || r == ".")
		}
		next := filepath.Join(w.nodes[cur].path, c)
		fd, err := syscall.Openat(w.fds[cur], c, unixOPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		switch e := errnoOf(err); {
		case e == syscall.ENOENT || e == syscall.ENOTDIR || e == syscall.EACCES:
			w.add(inode{path: next, seen: e != syscall.EACCES, parent: cur}, -1, c)
			for _, r := range rest { // what lies below, missing or unseen alike
				if r != "" && r != "." {
					next = filepath.Join(next, r)
					w.add(inode{path: next, seen: e != syscall.EACCES, parent: w.last()}, -1, r)
				}
			}
			w.errno, w.dangling = e, final && e != syscall.EACCES
			return w, nil
		case err != nil:
			w.close()
			return nil, unknowable("%s can't be opened to check it: %v", next, err)
		}
		n, err := describeFD(fd, next)
		if err != nil {
			syscall.Close(fd)
			w.close()
			return nil, err
		}
		n.parent = cur
		w.add(n, fd, c)
		if !n.link || last && !follow {
			cur = w.last()
			continue
		}
		if hops++; hops > maxHops {
			w.close()
			return nil, unknowable("%s has more than %d links on the way", p, maxHops)
		}
		t, err := readlinkAt(fd, "") // the link the walk holds and judged, never the name again
		if err != nil {
			w.close()
			return nil, unknowable("%s can't be read as a link: %v", next, err)
		}
		final = final || last // past this point the walk follows the last name's own chain
		if filepath.IsAbs(t) {
			cur = 0
		} // a relative target resolves from the directory holding the link: cur, still
		rest = append(strings.Split(t, "/"), rest...)
		w.steps = append(w.steps, filepath.Join(append([]string{w.nodes[cur].path}, rest...)...))
	}
	if cur != w.last() { // the path ends on a directory a link, "." or ".." led back to: that directory is the target
		fd, err := unix.FcntlInt(uintptr(w.fds[cur]), unix.F_DUPFD_CLOEXEC, 3)
		if err != nil {
			w.close()
			return nil, unknowable("%s can't be held: %v", w.nodes[cur].path, err)
		}
		w.add(w.nodes[cur], fd, w.names[cur])
	}
	return w, nil
}

func (w *pathWalk) add(n inode, fd int, name string) {
	w.nodes, w.fds, w.names = append(w.nodes, n), append(w.fds, fd), append(w.names, name)
}

// up takes ".." with the kernel's own openat, from the directory the walk has reached. It must land on the directory
// that one was looked up in, which the walk already holds; anything else (a directory reached some other way) the walk
// can't follow, and the path is unknowable. At "/", ".." is "/".
func (w *pathWalk) up(cur *int) error {
	fd, err := syscall.Openat(w.fds[*cur], "..", unixOPath|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return unknowable("%s/.. can't be opened: %v", w.nodes[*cur].path, err)
	}
	defer syscall.Close(fd)
	var st, want syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil {
		return unknowable("%s/.. can't be checked", w.nodes[*cur].path)
	}
	to := w.nodes[*cur].parent
	if to < 0 {
		to = 0
	}
	if syscall.Fstat(w.fds[to], &want) != nil || st.Dev != want.Dev || st.Ino != want.Ino {
		return unknowable("the kernel's parent of %s isn't the directory it was looked up in", w.nodes[*cur].path)
	}
	*cur = to
	return nil
}

// readlinkAt reads the link name in directory dfd, whole; with name "", the link dfd itself holds (O_PATH).
func readlinkAt(dfd int, name string) (string, error) {
	for size := 256; size <= 65536; size *= 4 {
		buf := make([]byte, size)
		n, err := unix.Readlinkat(dfd, name, buf)
		if err != nil {
			return "", err
		}
		if n < size {
			return string(buf[:n]), nil
		}
	}
	return "", syscall.ENAMETOOLONG
}

// describeFD is one inode's attributes, from its O_PATH descriptor: fstat, fstatfs, statx's mount-root attribute, and
// the ACL's extended attribute's size, an ACL that can't be ruled out counting as one. A mount point is told only by STATX_ATTR_MOUNT_ROOT, never by a change of
// device, which a Btrfs subvolume shows too while staying an entry its directory can rename; where the kernel can't
// say, the entry is judged as an ordinary one (TWN-4).
func describeFD(fd int, p string) (inode, error) {
	n := inode{path: p, seen: true, exists: true}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return n, unknowable("%s can't be checked: %v", p, err)
	}
	n.dir = st.Mode&syscall.S_IFMT == syscall.S_IFDIR
	n.link = st.Mode&syscall.S_IFMT == syscall.S_IFLNK
	n.ftype = st.Mode & syscall.S_IFMT
	n.uid, n.gid, n.mode, n.dev, n.ino = st.Uid, st.Gid, st.Mode&0o1777, uint64(st.Dev), st.Ino
	var fs syscall.Statfs_t
	if syscall.Fstatfs(fd, &fs) == nil {
		n.ro = fs.Flags&1 /* ST_RDONLY */ != 0
		n.procfs = fs.Type == 0x9fa0                    /* PROC_SUPER_MAGIC */
		n.noEntries = n.procfs || fs.Type == 0x62656572 /* SYSFS_MAGIC */
	}
	var sx unix.Statx_t
	if unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_BASIC_STATS, &sx) == nil &&
		sx.Attributes_mask&unix.STATX_ATTR_MOUNT_ROOT != 0 {
		n.mountPoint = sx.Attributes&unix.STATX_ATTR_MOUNT_ROOT != 0
	}
	if !n.link { // only "no such attribute" or "not supported" rules an ACL out; any other failure counts as one
		size, err := unix.Getxattr(fmt.Sprintf("/proc/self/fd/%d", fd), "system.posix_acl_access", nil)
		n.acl = err == nil && size > 0 || err != nil && err != unix.ENODATA && err != unix.EOPNOTSUPP
	}
	return n, nil
}

// canAt asks the kernel whether the agent as it is has access mode (faccessat, effective IDs) to node i of the walk:
// a directory through its own descriptor, anything else by its name in its directory, which the walk holds.
func (w *pathWalk) canAt(i int, mode uint32) error {
	if w.nodes[i].dir || w.nodes[i].parent < 0 {
		return syscall.Faccessat(w.fds[i], ".", mode, atEAccess)
	}
	return syscall.Faccessat(w.fds[w.nodes[i].parent], w.names[i], mode, atEAccess|unix.AT_SYMLINK_NOFOLLOW)
}
