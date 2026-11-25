//go:build linux

package probe

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
	"sandprobe/internal/obs"
)

func plannedEmpty(t *testing.T) obs.PlannedMark {
	t.Helper()
	m := plannedIn(t, t.TempDir(), "r1")
	m.Path = filepath.Join(m.Root, obs.EmptyMarkerPrefix+"r1")
	return m
}

func TestEmptyMarkerMetadataSurvivesRenumberingWithoutContentRead(t *testing.T) {
	m := plannedEmpty(t)
	p := markOne(t, m, "r1")
	if !p.Placed || p.Ino == 0 || p.Size != 0 {
		t.Fatal(p)
	}
	original := statEmptyMarker
	calls := 0
	t.Cleanup(func() { statEmptyMarker = original })
	statEmptyMarker = func(fd int, st *syscall.Stat_t) error {
		calls++
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
		if err != nil || flags&unix.O_PATH == 0 {
			t.Fatal("marker opened for data I/O", err)
		}
		return original(fd, st)
	}
	if got := recheckOne(p, "r1"); got.State != "survived" {
		t.Fatal(got)
	}
	replacement := filepath.Join(m.Root, "replacement")
	if err := os.WriteFile(replacement, nil, 0600); err != nil {
		t.Fatal(err)
	}
	st, err := os.Lstat(replacement)
	if err != nil || st.Sys().(*syscall.Stat_t).Ino == p.Ino {
		t.Fatal("fixture inode not distinct", err)
	}
	if err := os.Rename(replacement, m.Path); err != nil {
		t.Fatal(err)
	}
	if got := recheckOne(p, "r1"); got.State != "survived" {
		t.Fatal("empty namespace marker lost on inode renumbering", got)
	}
	if calls != 2 {
		t.Fatal("metadata proof wasn't exercised", calls)
	}
	if err := os.Remove(m.Path); err != nil {
		t.Fatal(err)
	}
	if got := recheckOne(p, "r1"); got.State != "absent" {
		t.Fatal(got)
	}
}

func TestEmptyMarkerRejectsContentAndWrongTypes(t *testing.T) {
	for _, kind := range []string{"nonempty", "symlink", "directory", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			m := plannedEmpty(t)
			p := markOne(t, m, "r1")
			if !p.Placed {
				t.Fatal(p)
			}
			if err := os.Remove(m.Path); err != nil {
				t.Fatal(err)
			}
			var err error
			switch kind {
			case "nonempty":
				err = os.WriteFile(m.Path, []byte("owned fixture, contents must remain unread"), 0000)
			case "symlink":
				err = os.Symlink("unread-target", m.Path)
			case "directory":
				err = os.Mkdir(m.Path, 0700)
			case "fifo":
				err = syscall.Mkfifo(m.Path, 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := recheckOne(p, "r1"); got.State != "unknown" {
				t.Fatal("substitution gained proof", got)
			}
		})
	}
}

func TestEmptyMarkerRejectsReplacementAndExistingPath(t *testing.T) {
	m := plannedEmpty(t)
	p := markOne(t, m, "r1")
	if !p.Placed {
		t.Fatal(p)
	}
	if again := markOne(t, m, "r1"); again.Placed {
		t.Fatal("existing path overwritten")
	}
	original := emptyMarkerUnchanged
	t.Cleanup(func() { emptyMarkerUnchanged = original })
	emptyMarkerUnchanged = func(dfd int, name string, st *syscall.Stat_t) bool {
		replacement := filepath.Join(m.Root, "replacement")
		if err := os.WriteFile(replacement, nil, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(replacement, m.Path); err != nil {
			t.Fatal(err)
		}
		return original(dfd, name, st)
	}
	if got := recheckOne(p, "r1"); got.State != "unknown" {
		t.Fatal("concurrent replacement accepted", got)
	}
}
