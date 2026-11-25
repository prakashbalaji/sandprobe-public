//go:build linux

package probe

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"sandprobe/internal/obs"
)

// PER-5's probe side (TWN-3): a read-only inventory of storage roots for the survey, the marks, and the recheck after
// the reset. The host plans, the provider resets, and only the host judges.

// pseudoFS hold nothing that survives anything: never storage roots.
var pseudoFS = map[string]bool{"proc": true, "sysfs": true, "cgroup": true, "cgroup2": true, "devpts": true, "mqueue": true,
	"debugfs": true, "tracefs": true, "securityfs": true, "pstore": true, "bpf": true, "configfs": true, "fusectl": true,
	"hugetlbfs": true, "binfmt_misc": true, "autofs": true, "nsfs": true, "devtmpfs": true}

// storageRoots is the survey's inventory: the agent's home, its working directory and each writable mount, each a real
// directory the agent can write and search, deduplicated by device and inode. Only stat and access are used. It says
// why when it is incomplete; the plan never relies on it alone for a root the adapter declares.
func storageRoots(incomplete *string) []obs.Root {
	type key struct{ dev, ino uint64 }
	byKey := map[key]*obs.Root{}
	var order []key
	add := func(path, kind, fstype, source string) {
		real, err := filepath.EvalSymlinks(path)
		if err != nil || path == "" {
			return
		}
		var st syscall.Stat_t
		if syscall.Lstat(real, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFDIR ||
			syscall.Faccessat(unixAtFDCWD, real, 2|1 /* W_OK|X_OK */, atEAccess) != nil {
			return
		}
		k := key{uint64(st.Dev), st.Ino}
		if r, ok := byKey[k]; ok {
			if !slices.Contains(r.Kinds, kind) {
				r.Kinds = append(r.Kinds, kind)
			}
			return
		}
		if len(order) == 64 {
			*incomplete = "more than 64 storage roots"
			return
		}
		byKey[k] = &obs.Root{Path: real, Kinds: []string{kind}, Dev: k.dev, Ino: k.ino, FSType: fstype, Source: source}
		order = append(order, k)
	}
	add(home(), "home", "", "")
	if wd, err := os.Getwd(); err == nil {
		add(wd, "wd", "", "")
	}
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		*incomplete = "mountinfo couldn't be read"
	} else {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			// id parent major:minor root mountpoint options [optional...] - fstype source superoptions
			pre, post, ok := strings.Cut(sc.Text(), " - ")
			a, b := strings.Fields(pre), strings.Fields(post)
			if !ok || len(a) < 6 || len(b) < 2 || pseudoFS[b[0]] || !slices.Contains(strings.Split(a[5], ","), "rw") {
				continue
			}
			add(unescapeMount(a[4]), "mount", b[0], b[1])
		}
		if sc.Err() != nil {
			*incomplete = "mountinfo didn't read to its end"
		}
		f.Close()
	}
	roots := make([]obs.Root, 0, len(order))
	for _, k := range order {
		roots = append(roots, *byKey[k])
	}
	return roots
}

// unescapeMount undoes mountinfo's octal escapes (\040 for a space).
func unescapeMount(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

var runIDShape = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)

func bootID() string {
	b, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
	return strings.TrimSpace(string(b))
}

// markerName accepts only the exact regular-file or EVD-15 link namespace for this run.
func markerName(root, path, runID string) (string, bool) {
	name := obs.MarkerPrefix + runID
	if path == filepath.Join(root, obs.LinkMarkerPrefix+runID) {
		name = obs.LinkMarkerPrefix + runID
	}
	if path == filepath.Join(root, obs.EmptyMarkerPrefix+runID) {
		name = obs.EmptyMarkerPrefix + runID
	}
	return name, runIDShape.MatchString(runID) && filepath.IsAbs(root) && path == filepath.Join(root, name)
}

// Mark places each planned marker (SBX-1): the root pinned O_PATH|O_DIRECTORY|O_NOFOLLOW and confirmed to be the
// directory the survey saw, then the marker created exclusively, never following a link, holding only the run id.
func Mark(in obs.MarkInput) *obs.MarkDoc {
	d := &obs.MarkDoc{Schema: obs.MarkSchema, RunID: in.RunID, Nonce: in.Nonce, BoxID: in.BoxID, BootID: bootID()}
	for _, m := range in.Marks {
		p := obs.Placed{Root: m.Root, Path: m.Path}
		p.Ino, p.Size, p.Why = place(m, in.RunID)
		p.Placed = p.Why == ""
		d.Marks = append(d.Marks, p)
	}
	return d
}

func place(m obs.PlannedMark, runID string) (uint64, int64, string) {
	name, ok := markerName(m.Root, m.Path, runID)
	if !ok {
		return 0, 0, "not a marker path this run may create"
	}
	dfd, err := syscall.Open(m.Root, unixOPath|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0) // no read permission needed
	if err != nil {
		return 0, 0, "the root can't be opened: " + errName(errnoOf(err))
	}
	defer syscall.Close(dfd)
	if m.Dev == 0 && m.Ino == 0 {
		return 0, 0, unlisted(dfd)
	}
	var rst syscall.Stat_t
	if syscall.Fstat(dfd, &rst) != nil || uint64(rst.Dev) != m.Dev || rst.Ino != m.Ino {
		return 0, 0, "the root isn't the directory the survey saw"
	}
	if name == obs.LinkMarkerPrefix+runID {
		// EVD-15: symlinkat is exclusive; no target is opened, followed or read.
		if err := unix.Symlinkat(runID, dfd, name); err != nil {
			return 0, 0, "the metadata marker can't be created: " + errName(errnoOf(err))
		}
		ino, why, absent := linkMarkerProof(dfd, name, runID)
		if absent {
			why = "the created metadata marker disappeared"
		}
		if why != "" {
			return 0, 0, why
		}
		return ino, int64(len(runID)), ""
	}
	if name == obs.EmptyMarkerPrefix+runID {
		return placeEmptyMarker(dfd, name)
	}
	fd, err := syscall.Openat(dfd, name, syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_WRONLY|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return 0, 0, "the marker can't be created: " + errName(errnoOf(err))
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	if _, err := io.WriteString(f, runID); err != nil {
		return 0, 0, "the marker couldn't be written" // it may exist, unconfirmed: the host lists it
	}
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil {
		return 0, 0, "the marker couldn't be checked"
	}
	return st.Ino, st.Size, ""
}

// unlisted says why a planned root the survey didn't list takes no marker (TWN-3). The survey lists only roots the
// agent can write and search, so the usual answer is that its current permissions refuse; that says nothing of the
// rest of the root's storage, so it is never the root's negative. Only faccessat on the root, pinned with O_PATH so one
// the agent can't read is still diagnosed: nothing is created.
func unlisted(dfd int) string {
	err := syscall.Faccessat(dfd, ".", 2|1 /* W_OK|X_OK */, atEAccess)
	switch e := errnoOf(err); {
	case e == syscall.EACCES || e == syscall.EROFS:
		return "its current permissions don't let the agent write it (" + errName(e) + "), so the survey didn't list it; " +
			"that doesn't show the agent can't write elsewhere on its storage"
	case err == nil:
		return "the survey didn't list it, though the agent can write it now"
	default:
		return "the survey didn't list it, and whether the agent can write it can't be told (" + errName(e) + ")"
	}
}

// Recheck looks for each placed marker after the reset (TWN-3): pinned with O_PATH|O_NOFOLLOW under the root pinned
// O_PATH|O_DIRECTORY|O_NOFOLLOW, read only when it is a regular file with the placed inode and length, and then only the run
// id and the end after it. Anything else at that name is unknown and unread; absence is ENOENT under the opened root.
// It also observes PER-1 to PER-4's targets, for the host to judge severity. It removes nothing (SBX-1).
func Recheck(in obs.RecheckInput) *obs.RecheckDoc {
	d := &obs.RecheckDoc{Schema: obs.RecheckSchema, RunID: in.RunID, Nonce: in.Nonce, BoxID: in.BoxID, BootID: bootID()}
	for _, m := range in.Marks {
		r := obs.Rechecked{Root: m.Root}
		if !m.Placed {
			r.State, r.Why = "unknown", "never placed"
		} else {
			r.State, r.Why = recheck(m, in.RunID)
		}
		d.Marks = append(d.Marks, r)
	}
	e := &env{home: home()}
	for _, name := range in.Startup {
		path := e.expand(name)
		s := obs.Startup{Name: name, Path: path, State: "unknown"}
		if t, err := writeCheck(name, path); err == nil {
			s.State = t.State
		}
		d.Startup = append(d.Startup, s)
	}
	return d
}

func recheck(m obs.Placed, runID string) (string, string) {
	name, ok := markerName(m.Root, m.Path, runID)
	if !ok {
		return "unknown", "not this run's marker path"
	}
	dfd, err := syscall.Open(m.Root, unixOPath|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0) // no read permission needed
	if err != nil {
		return "unknown", "the root can't be opened: " + errName(errnoOf(err))
	}
	defer syscall.Close(dfd)
	if name == obs.EmptyMarkerPrefix+runID {
		return emptyMarkerProof(dfd, name)
	}
	if name == obs.LinkMarkerPrefix+runID {
		_, why, absent := linkMarkerProof(dfd, name, runID)
		if absent {
			return "absent", ""
		}
		if why != "" {
			return "unknown", why
		}
		return "survived", ""
	}
	pfd, err := syscall.Openat(dfd, name, unixOPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	switch e := errnoOf(err); {
	case e == syscall.ENOENT:
		return "absent", ""
	case err != nil:
		return "unknown", "the marker can't be pinned: " + errName(e)
	}
	defer syscall.Close(pfd)
	var st syscall.Stat_t
	switch {
	case syscall.Fstat(pfd, &st) != nil:
		return "unknown", "the marker can't be checked"
	case st.Mode&syscall.S_IFMT != syscall.S_IFREG:
		return "unknown", "something other than a regular file is at the marker's name; unread"
	// TWN-3: explain which metadata guard failed without reading the file or
	// treating filesystem behavior as proof of marker identity.
	case st.Ino != m.Ino && st.Size != m.Size:
		return "unknown", "the marker's inode and length differ from the placed marker; unread"
	case st.Ino != m.Ino:
		return "unknown", "the marker's inode differs from the placed marker; unread"
	case st.Size != m.Size:
		return "unknown", "the marker's length differs from the placed marker; unread"
	}
	rfd, err := syscall.Open(fmt.Sprintf("/proc/self/fd/%d", pfd), syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return "unknown", "the marker can't be opened"
	}
	f := os.NewFile(uintptr(rfd), name)
	defer f.Close()
	got := make([]byte, len(runID)+1) // the run id, and a read past it that must find the end
	n, err := io.ReadFull(f, got)
	switch {
	case err != io.ErrUnexpectedEOF:
		return "unknown", "the marker didn't read as exactly its length, then its end"
	case n != len(runID) || !bytes.Equal(got[:n], []byte(runID)):
		return "unknown", "the marker doesn't hold exactly this run's id"
	}
	return "survived", ""
}

// EVD-15: read only the pinned link's bounded metadata, never a target's contents.
// The post-read name check rejects a replacement during this measurement.
func linkMarkerProof(dfd int, name, runID string) (uint64, string, bool) {
	fd, err := syscall.Openat(dfd, name, unixOPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if errnoOf(err) == syscall.ENOENT {
		return 0, "", true
	}
	if err != nil {
		return 0, "the metadata marker can't be pinned: " + errName(errnoOf(err)), false
	}
	defer syscall.Close(fd)
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Ino == 0 || st.Mode&syscall.S_IFMT != syscall.S_IFLNK {
		return 0, "the metadata marker isn't a symbolic link; target unread", false
	}
	buf := make([]byte, len(runID)+1)
	n, err := readMarkerLink(fd, buf)
	if err != nil {
		return 0, "the marker link metadata can't be read: " + errName(errnoOf(err)), false
	}
	if n != len(runID) || !bytes.Equal(buf[:n], []byte(runID)) {
		return 0, "the marker link metadata doesn't match this run; target unread", false
	}
	var after unix.Stat_t
	if unix.Fstatat(dfd, name, &after, unix.AT_SYMLINK_NOFOLLOW) != nil || after.Mode&unix.S_IFMT != unix.S_IFLNK || uint64(after.Dev) != uint64(st.Dev) || after.Ino != st.Ino {
		return 0, "the metadata marker changed during measurement; target unread", false
	}
	return st.Ino, "", false
}

var readMarkerLink = func(fd int, buf []byte) (int, error) { return unix.Readlinkat(fd, "", buf) }

func placeEmptyMarker(dfd int, name string) (ino uint64, size int64, why string) {
	fd, err := syscall.Openat(dfd, name, syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_WRONLY|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return 0, 0, "the empty metadata marker can't be created: " + errName(errnoOf(err))
	}
	defer func() {
		if err := syscall.Close(fd); err != nil && why == "" {
			ino = 0
			why = "the empty metadata marker couldn't be closed"
		}
	}()
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Ino == 0 || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Size != 0 {
		return 0, 0, "the new metadata marker isn't an identifiable empty regular file"
	}
	var after unix.Stat_t
	if unix.Fstatat(dfd, name, &after, unix.AT_SYMLINK_NOFOLLOW) != nil || after.Ino != st.Ino || uint64(after.Dev) != uint64(st.Dev) || after.Mode&unix.S_IFMT != unix.S_IFREG || after.Size != 0 {
		return 0, 0, "the empty metadata marker changed during placement"
	}
	return st.Ino, 0, ""
}

func emptyMarkerProof(dfd int, name string) (string, string) {
	fd, err := syscall.Openat(dfd, name, unixOPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if errnoOf(err) == syscall.ENOENT {
		return "absent", ""
	}
	if err != nil {
		return "unknown", "the empty metadata marker can't be pinned: " + errName(errnoOf(err))
	}
	defer syscall.Close(fd)
	var st syscall.Stat_t
	if statEmptyMarker(fd, &st) != nil || st.Ino == 0 || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Size != 0 {
		return "unknown", "the metadata marker isn't an empty regular file; contents unread"
	}
	if !emptyMarkerUnchanged(dfd, name, &st) {
		return "unknown", "the empty metadata marker changed during measurement; contents unread"
	}
	return "survived", ""
}

var emptyMarkerUnchanged = func(dfd int, name string, st *syscall.Stat_t) bool {
	var after unix.Stat_t
	return unix.Fstatat(dfd, name, &after, unix.AT_SYMLINK_NOFOLLOW) == nil && after.Mode&unix.S_IFMT == unix.S_IFREG && after.Size == 0 && after.Ino == st.Ino && uint64(after.Dev) == uint64(st.Dev)
}
var statEmptyMarker = syscall.Fstat
