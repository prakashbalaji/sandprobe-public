//go:build linux

package quick

import (
	"encoding/json"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNamesOnlyAndBounds(t *testing.T) {
	names, cut := environment([]string{"API_TOKEN=must-never-appear", "PATH=private-value", "PASSWORD=another-private-value"})
	b, _ := json.Marshal(names)
	if cut || string(b) != `["API_TOKEN","PASSWORD"]` {
		t.Fatal("names inventory mismatch")
	}
	env := make([]string, 257)
	for i := range env {
		env[i] = "TOKEN=x"
	}
	if _, cut := environment(env); !cut {
		t.Fatal("unbounded environment")
	}
	if _, cut := environment([]string{strings.Repeat("X", 257) + "=x"}); !cut {
		t.Fatal("unbounded name")
	}
}
func TestProcStatus(t *testing.T) {
	good := "CapEff:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n"
	var id Identity
	parseStatus([]byte(good), &id)
	if id.Status != "observed" || *id.NoNewPrivs != 1 {
		t.Fatal("canonical status rejected")
	}
	for _, s := range []string{"", "CapEff:\n", good + "NoNewPrivs: 0\n", strings.ReplaceAll(good, "Seccomp:\t2", "Seccomp:\t9"), strings.ReplaceAll(good, "0000000000000000", "not-hex")} {
		id := Identity{Status: "unknown"}
		parseStatus([]byte(s), &id)
		if id.Status != "unknown" || id.NoNewPrivs != nil || id.CapEffective != "" {
			t.Fatal("malformed status assessed")
		}
	}
}
func TestMetadataNoFollow(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("secret-fixture-not-read"), 0600); err != nil {
		t.Fatal(err)
	}
	p := metadata(file)
	if p.Status != "metadata_observed" || p.Mode == nil {
		t.Fatal("metadata missing")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if metadata(link).Status != "symlink_not_followed" {
		t.Fatal("final symlink followed")
	}
	parent := filepath.Join(dir, "parent")
	if err := os.Symlink(dir, parent); err != nil {
		t.Fatal(err)
	}
	if metadata(filepath.Join(parent, "file")).Status != "unknown" {
		t.Fatal("ancestor symlink followed")
	}
	if metadata(filepath.Join(dir, "missing")).Status != "unknown" {
		t.Fatal("missing path assessed")
	}
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if metadata(fifo).Status != "metadata_observed" {
		t.Fatal("FIFO metadata unavailable")
	}
}
func TestPathLimits(t *testing.T) {
	for _, paths := range [][]string{{"relative"}, {"/tmp/../etc"}, {"/a\x00b"}, {"/" + strings.Repeat("a", 1024)}, {"/" + strings.Repeat("a/", 34) + "a"}, make([]string, 33)} {
		if ValidatePaths(paths) == nil {
			t.Fatal("unbounded/unsafe paths accepted")
		}
	}
	if ValidatePaths([]string{"/", "/tmp/file"}) != nil {
		t.Fatal("normal paths rejected")
	}
}

func TestPinnedProcStatus(t *testing.T) {
	for _, tc := range []string{"good", "missing", "ancestor_symlink", "final_symlink", "fifo", "oversize", "wrong_filesystem", "pid_namespace_mismatch"} {
		t.Run(tc, func(t *testing.T) {
			root := t.TempDir()
			self := "123"
			if tc == "pid_namespace_mismatch" {
				self = "124"
			}
			if err := os.Symlink(self, filepath.Join(root, "self")); err != nil {
				t.Fatal(err)
			}
			pidDir := filepath.Join(root, "123")
			if tc == "ancestor_symlink" {
				if err := os.Symlink(t.TempDir(), pidDir); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Mkdir(pidDir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(pidDir, "status")
			switch tc {
			case "good", "wrong_filesystem":
				_ = os.WriteFile(path, []byte("fixture-only"), 0600)
			case "oversize":
				_ = os.WriteFile(path, []byte(strings.Repeat("x", (64<<10)+1)), 0600)
			case "final_symlink":
				_ = os.Symlink("/not-read", path)
			case "fifo":
				if err := unix.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			}
			fd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(fd)
			b, err := readStatusAt(fd, 123, func(int) bool { return tc != "wrong_filesystem" })
			if tc == "good" {
				if err != nil || string(b) != "fixture-only" {
					t.Fatal("fixture read failed")
				}
			} else if err == nil || b != nil {
				t.Fatal("unsafe proc input accepted")
			}
		})
	}
}
func TestMaximumOutputBudget(t *testing.T) {
	d := Doc{EnvironmentNames: []string{}, Paths: []Path{}}
	for i := 0; i < 256; i++ {
		d.EnvironmentNames = append(d.EnvironmentNames, strings.Repeat("\x1b", 251)+"TOKEN")
	}
	for i := 0; i < 32; i++ {
		d.Paths = append(d.Paths, Path{Name: "/" + strings.Repeat("\x1b", 1023), Status: "unknown"})
	}
	b, _ := json.Marshal(d)
	// Worst-case escaping can exceed the limit: entrypoint must reject, not truncate.
	if len(b) < MaxOutput {
		t.Fatal("fixture no longer exercises output guard")
	}
}
