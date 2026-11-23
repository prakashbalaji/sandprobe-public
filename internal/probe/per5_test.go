//go:build linux

package probe

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"sandprobe/internal/obs"
)

// The survey's inventory: real directories the agent can write, one entry per directory however it's reached.
func TestStorageRoots(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	chdir(t, dir)
	n, why := 0, ""
	for _, r := range storageRoots(&why) {
		if r.Path == dir {
			n++
			if len(r.Kinds) != 2 {
				t.Errorf("home and wd are one directory: want one root with both kinds, got %+v", r)
			}
		}
		if r.Path == "/proc" || r.FSType == "proc" || r.FSType == "sysfs" {
			t.Errorf("a pseudo filesystem is no storage root: %+v", r)
		}
	}
	if n != 1 {
		t.Errorf("want the directory once, got %d", n)
	}
	if why != "" {
		t.Errorf("a plain container's inventory is complete, got %q", why)
	}
}

func plannedIn(t *testing.T, root, runID string) obs.PlannedMark {
	var st syscall.Stat_t
	if err := syscall.Stat(root, &st); err != nil {
		t.Fatal(err)
	}
	return obs.PlannedMark{Root: root, Path: filepath.Join(root, obs.MarkerPrefix+runID), Dev: uint64(st.Dev), Ino: st.Ino}
}

func markOne(t *testing.T, m obs.PlannedMark, runID string) obs.Placed {
	d := Mark(obs.MarkInput{RunID: runID, Marks: []obs.PlannedMark{m}})
	if len(d.Marks) != 1 || d.BootID == "" {
		t.Fatalf("want one mark and a boot id, got %+v", d)
	}
	return d.Marks[0]
}

func recheckOne(p obs.Placed, runID string) obs.Rechecked {
	return Recheck(obs.RecheckInput{RunID: runID, Marks: []obs.Placed{p}}).Marks[0]
}

func TestMarkAndRecheck(t *testing.T) {
	const run = "r1"
	fresh := func() (string, obs.Placed) {
		root := t.TempDir()
		p := markOne(t, plannedIn(t, root, run), run)
		if !p.Placed || p.Size != int64(len(run)) {
			t.Fatalf("want the marker placed, holding the run id, got %+v", p)
		}
		return root, p
	}

	root, p := fresh()
	if r := recheckOne(p, run); r.State != "survived" {
		t.Errorf("the placed marker: want survived, got %+v", r)
	}
	if _, err := os.Lstat(p.Path); err != nil {
		t.Error("the recheck must remove nothing (SBX-1)")
	}
	os.Remove(p.Path)
	if r := recheckOne(p, run); r.State != "absent" {
		t.Errorf("a cleared root: want absent, got %+v", r)
	}

	// an unrelated regular file holding the run id, at the marker's name: not the placed inode, so unread, unknown
	root, p = fresh()
	sub := filepath.Join(root, "substitute")
	os.WriteFile(sub, []byte(run), 0o600)
	os.Rename(sub, p.Path)
	if r := recheckOne(p, run); r.State != "unknown" {
		t.Errorf("a substitute file: want unknown, got %+v", r)
	}

	// a FIFO at the marker's name: never opened for reading, so never blocks
	root, p = fresh()
	os.Remove(p.Path)
	if err := syscall.Mkfifo(p.Path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan obs.Rechecked, 1)
	go func() { done <- recheckOne(p, run) }()
	select {
	case r := <-done:
		if r.State != "unknown" {
			t.Errorf("a FIFO: want unknown, got %+v", r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the recheck blocked on a FIFO")
	}

	// a symlink at the marker's name, to a file holding the run id: pinned as the link itself, unknown
	root, p = fresh()
	target := filepath.Join(root, "elsewhere")
	os.WriteFile(target, []byte(run), 0o600)
	os.Remove(p.Path)
	os.Symlink(target, p.Path)
	if r := recheckOne(p, run); r.State != "unknown" {
		t.Errorf("a symlink: want unknown, got %+v", r)
	}

	// the marker's own inode, at its length, holding something else: written over in place
	root, p = fresh()
	f, _ := os.OpenFile(p.Path, os.O_WRONLY, 0)
	f.WriteString("r9")
	f.Close()
	if r := recheckOne(p, run); r.State != "unknown" {
		t.Errorf("the marker's content changed: want unknown, got %+v", r)
	}

	// the root gone after the reset
	root, p = fresh()
	os.RemoveAll(root)
	if r := recheckOne(p, run); r.State != "unknown" {
		t.Errorf("a missing root: want unknown, got %+v", r)
	}

	// a mark that wasn't placed is never rechecked as absent
	if r := recheckOne(obs.Placed{Root: "/x", Path: "/x/" + obs.MarkerPrefix + run}, run); r.State != "unknown" {
		t.Errorf("never placed: want unknown, got %+v", r)
	}
}

func TestMarkRefuses(t *testing.T) {
	const run = "r1"
	root := t.TempDir()
	m := plannedIn(t, root, run)

	bad := m
	bad.Ino++ // the directory changed since the survey
	if p := markOne(t, bad, run); p.Placed {
		t.Error("a root that isn't the surveyed directory: want no marker")
	}
	bad = m
	bad.Path = filepath.Join(root, "authorized_keys") // only <root>/.sandprobe-<run id> is ever created
	if p := markOne(t, bad, run); p.Placed {
		t.Error("a path that isn't this run's marker: want nothing created")
	}
	if _, err := os.Lstat(bad.Path); err == nil {
		t.Error("the probe created a file it may not")
	}
	os.WriteFile(m.Path, []byte("someone else's"), 0o600) // O_EXCL: never overwritten
	if p := markOne(t, m, run); p.Placed {
		t.Error("an existing file at the marker's name: want no marker")
	}
	if b, _ := os.ReadFile(m.Path); string(b) != "someone else's" {
		t.Error("an existing file was overwritten")
	}
	fresh := t.TempDir() // nothing at its marker's name, so only O_NOFOLLOW can refuse
	link := filepath.Join(t.TempDir(), "rootlink")
	os.Symlink(fresh, link)
	lm := plannedIn(t, fresh, run)
	lm.Root, lm.Path = link, filepath.Join(link, obs.MarkerPrefix+run)
	if p := markOne(t, lm, run); p.Placed {
		t.Error("a root reached through a symlink: want no marker (O_NOFOLLOW)")
	}
}

// A planned root the survey didn't list has no directory identity: it takes no marker, and the mark says why, usually
// that the agent can't write it, which is never that root's negative (TWN-3). Nothing is created either way.
func TestMarkUnlisted(t *testing.T) {
	const run = "r1"
	cases := map[string]string{t.TempDir(): "the survey didn't list it, though the agent can write it now",
		"/usr": "the agent can't write it (EACCES), so the survey didn't list it"}
	if root {
		cases["/usr"] = "the survey didn't list it, though the agent can write it now"
	}
	for dir, want := range cases {
		m := obs.PlannedMark{Root: dir, Path: filepath.Join(dir, obs.MarkerPrefix+run)}
		if p := markOne(t, m, run); p.Placed || !strings.Contains(p.Why, want) {
			t.Errorf("%s, unlisted: want no marker because %q, got %+v", dir, want, p)
		}
		if _, err := os.Lstat(m.Path); err == nil {
			t.Errorf("a marker was created in the unlisted root %s", dir)
		}
	}
}

// The recheck observes PER-1 to PER-4's targets for the host; it judges nothing.
func TestRecheckStartup(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	os.WriteFile(filepath.Join(dir, ".bashrc"), nil, 0o644)
	d := Recheck(obs.RecheckInput{RunID: "r1", Startup: []string{"~/.bashrc"}})
	if len(d.Startup) != 1 || d.Startup[0].Path != filepath.Join(dir, ".bashrc") || d.Startup[0].State != "found" {
		t.Errorf("want ~/.bashrc observed writable at its path, got %+v", d.Startup)
	}
}
