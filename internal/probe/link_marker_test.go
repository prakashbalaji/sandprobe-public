//go:build linux

package probe

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"sandprobe/internal/obs"
)

func plannedLink(t *testing.T) obs.PlannedMark {
	t.Helper()
	m := plannedIn(t, t.TempDir(), "r1")
	m.Path = filepath.Join(m.Root, obs.LinkMarkerPrefix+"r1")
	return m
}

func TestLinkMarkerSurvivesRenumberingWithoutFollowingTarget(t *testing.T) {
	m := plannedLink(t)
	p := markOne(t, m, "r1")
	if !p.Placed || p.Ino == 0 || p.Size != 2 {
		t.Fatalf("metadata marker not placed: %+v", p)
	}
	if got := recheckOne(p, "r1"); got.State != "survived" {
		t.Fatal(got)
	}
	// Create the replacement while the original exists, guaranteeing a distinct
	// inode. This calibrates logical metadata persistence on a renumbering FS.
	replacement := filepath.Join(m.Root, "replacement")
	if err := os.Symlink("r1", replacement); err != nil {
		t.Fatal(err)
	}
	st, err := os.Lstat(replacement)
	if err != nil || st.Sys().(*syscall.Stat_t).Ino == p.Ino {
		t.Fatal("fixture did not obtain a distinct inode", err)
	}
	if err := os.Rename(replacement, m.Path); err != nil {
		t.Fatal(err)
	}
	if got := recheckOne(p, "r1"); got.State != "survived" {
		t.Fatal("matching link metadata lost on inode renumbering", got)
	}
	if err := os.Remove(m.Path); err != nil {
		t.Fatal(err)
	}
	if got := recheckOne(p, "r1"); got.State != "absent" {
		t.Fatal(got)
	}
}

func TestLinkMarkerRejectsWrongTypeAndMetadata(t *testing.T) {
	for _, kind := range []string{"regular", "directory", "fifo", "wrong-link", "long-link", "file-target", "dangling"} {
		t.Run(kind, func(t *testing.T) {
			m := plannedLink(t)
			p := markOne(t, m, "r1")
			if !p.Placed {
				t.Fatal(p)
			}
			if err := os.Remove(m.Path); err != nil {
				t.Fatal(err)
			}
			var err error
			switch kind {
			case "regular":
				err = os.WriteFile(m.Path, []byte("r1"), 0600)
			case "directory":
				err = os.Mkdir(m.Path, 0700)
			case "fifo":
				err = syscall.Mkfifo(m.Path, 0600)
			case "wrong-link":
				err = os.Symlink("r2", m.Path)
			case "long-link":
				err = os.Symlink("r1-extra", m.Path)
			case "file-target":
				target := filepath.Join(m.Root, "unread-fixture")
				if err = os.WriteFile(target, []byte("owned fixture, must not read"), 0000); err == nil {
					err = os.Symlink(target, m.Path)
				}
			case "dangling":
				err = os.Symlink("absent-target", m.Path)
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := recheckOne(p, "r1"); got.State != "unknown" {
				t.Fatalf("substitution became usable proof: %+v", got)
			}
		})
	}
}

func TestLinkMarkerRejectsConcurrentReplacementAndUnsupportedRead(t *testing.T) {
	m := plannedLink(t)
	p := markOne(t, m, "r1")
	if !p.Placed {
		t.Fatal(p)
	}
	original := readMarkerLink
	t.Cleanup(func() { readMarkerLink = original })
	readMarkerLink = func(fd int, buf []byte) (int, error) {
		var st syscall.Stat_t
		if err := syscall.Fstat(fd, &st); err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFLNK {
			t.Fatal("metadata read received a followed target", err)
		}
		n, err := original(fd, buf)
		replacement := filepath.Join(m.Root, "replacement")
		if err := os.Symlink("r1", replacement); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(replacement, m.Path); err != nil {
			t.Fatal(err)
		}
		return n, err
	}
	if got := recheckOne(p, "r1"); got.State != "unknown" {
		t.Fatal("concurrent replacement accepted", got)
	}
	readMarkerLink = func(int, []byte) (int, error) { return 0, syscall.ENOSYS }
	if got := recheckOne(p, "r1"); got.State != "unknown" {
		t.Fatal("unsupported read gained a fallback", got)
	}
}

func TestLinkMarkerCreationIsExclusiveAndRootBound(t *testing.T) {
	m := plannedLink(t)
	if err := os.WriteFile(m.Path, []byte("owned fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := markOne(t, m, "r1"); got.Placed {
		t.Fatal("existing path overwritten", got)
	}
	m = plannedLink(t)
	m.Ino++
	if got := markOne(t, m, "r1"); got.Placed {
		t.Fatal("changed root accepted", got)
	}
	if _, err := os.Lstat(m.Path); !os.IsNotExist(err) {
		t.Fatal("changed root was written", err)
	}
}
