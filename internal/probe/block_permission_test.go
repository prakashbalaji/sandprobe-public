//go:build linux

package probe

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"sandprobe/internal/catalog"
	"sandprobe/internal/obs"

	"golang.org/x/sys/unix"
)

func TestDeclaredBlockDevices(t *testing.T) {
	ck, _ := catalog.Get("AMP-8.blk")
	defer func(f func() uint64) { agentCaps = f }(agentCaps)
	agentCaps = func() uint64 { return 0 }
	e := &env{in: Input{Targets: map[string][]string{}, Discover: map[string][]string{ck.ID: {"block_devices"}}}, root: root, tw: &twins{}}
	if got := assessBlockDevices(e, ck, nil); got.Result != obs.ScopedOut {
		t.Fatal("empty discovery without a declaration", got)
	}
	dir := t.TempDir()
	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, []byte("owned fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{regular, filepath.Join(dir, "missing"), "relative"} {
		e.in.Targets[ck.ID] = []string{path}
		if got := assessBlockDevices(e, ck, nil); got.Result != obs.Unknown {
			t.Fatalf("unmeasurable declared path became a negative: %+v", got)
		}
	}
	// Root-only contract fixture: synthetic 0:0, not an attached disk; metadata only.
	block := syntheticBlockNode(t, dir, "custom-block")
	e.in.Targets[ck.ID] = []string{block}
	got := assessBlockDevices(e, ck, nil)
	if got.Result != obs.Finding || got.Variant != "readable_block_device" || got.Proof == nil || len(got.Proof.Targets) != 1 || got.Proof.Targets[0].Name != block || got.Proof.Targets[0].Rule != "" || got.Proof.Discovered["block_devices"] != 0 {
		t.Fatalf("declared block lost its measurement with empty discovery: %+v", got)
	}
}

func TestBlockPermissionRejectsOtherTypesAndMissingPaths(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, []byte("owned fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	original := readPermAt
	readPermAt = func(int) error { t.Fatal("non-block type reached permission call"); return nil }
	t.Cleanup(func() { readPermAt = original })
	for _, path := range []string{regular, fifo, dir, link, filepath.Join(dir, "missing")} {
		got, err := blockPermCheck(path, path)
		if !errors.Is(err, errUnknowable) || got.State != "" {
			t.Fatalf("non-block target gained evidence: %+v %v", got, err)
		}
	}
}

func syntheticBlockNode(t *testing.T, dir, name string) string {
	t.Helper()
	if !root {
		t.Skip("synthetic 0:0 device-node creation runs in the root contract container")
	}
	path := filepath.Join(dir, name)
	if err := syscall.Mknod(path, syscall.S_IFBLK|0600, 0); err != nil {
		t.Fatalf("create owned synthetic block 0:0 fixture: %v", err)
	}
	return path
}

func TestBlockPermissionPinsSyntheticNodeAndRejectsCharacterDevice(t *testing.T) {
	dir := t.TempDir()
	block := syntheticBlockNode(t, dir, "block")
	character := filepath.Join(dir, "character")
	if err := syscall.Mknod(character, syscall.S_IFCHR|0600, 1); err != nil {
		t.Fatal(err)
	}
	original := readPermAt
	calls := 0
	readPermAt = func(fd int) error {
		calls++
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
		if err != nil || flags&unix.O_PATH == 0 {
			t.Fatal("permission call did not receive metadata-only descriptor", err)
		}
		var st syscall.Stat_t
		if err := syscall.Fstat(fd, &st); err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFBLK || st.Rdev != 0 {
			t.Fatal("not synthetic pinned block 0:0", err)
		}
		return original(fd)
	}
	t.Cleanup(func() { readPermAt = original })
	got, err := blockPermCheck(block, block)
	if err != nil || (got.State != "found" && got.State != "refused") || calls != 1 {
		t.Fatalf("pinned block measurement: %+v %v", got, err)
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(block, alias); err != nil {
		t.Fatal(err)
	}
	if aliased, err := blockPermCheck(alias, alias); err != nil || aliased.State != got.State || calls != 2 {
		t.Fatal("stable block alias lost its metadata measurement", aliased, err)
	}
	if got, err := blockPermCheck(character, character); !errors.Is(err, errUnknowable) || got.State != "" || calls != 2 {
		t.Fatal("character device became a block-device result", got, err)
	}
}

func TestBlockPermissionReplacementAndRetargetingStayUnknown(t *testing.T) {
	for _, kind := range []string{"regular", "character", "block", "missing", "symlink", "symlink-block"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			block := syntheticBlockNode(t, dir, "original")
			path := block
			if kind == "symlink" || kind == "symlink-block" {
				path = filepath.Join(dir, "alias")
				if err := os.Symlink(block, path); err != nil {
					t.Fatal(err)
				}
			}
			original := readPermAt
			calls := 0
			readPermAt = func(fd int) error {
				calls++
				var st syscall.Stat_t
				if err := syscall.Fstat(fd, &st); err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFBLK {
					t.Fatal("original block not pinned", err)
				}
				if err := os.Rename(path, path+"-saved"); err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "regular":
					if err := os.WriteFile(path, []byte("replacement fixture"), 0600); err != nil {
						t.Fatal(err)
					}
				case "symlink", "symlink-block":
					replacement := filepath.Join(dir, "replacement")
					if kind == "symlink-block" {
						if err := syscall.Mknod(replacement, syscall.S_IFBLK|0600, 0); err != nil {
							t.Fatal(err)
						}
					} else if err := os.WriteFile(replacement, []byte("replacement fixture"), 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(replacement, path); err != nil {
						t.Fatal(err)
					}
				case "character":
					if err := syscall.Mknod(path, syscall.S_IFCHR|0600, 1); err != nil {
						t.Fatal(err)
					}
				case "block":
					if err := syscall.Mknod(path, syscall.S_IFBLK|0600, 0); err != nil {
						t.Fatal(err)
					}
				}
				// Both permitted and refused outcomes must be discarded after observed replacement.
				if kind == "regular" || kind == "block" {
					return nil
				}
				return syscall.EACCES
			}
			t.Cleanup(func() { readPermAt = original })
			got, err := blockPermCheck(path, path)
			if !errors.Is(err, errUnknowable) || got.State != "" || calls != 1 {
				t.Fatalf("replacement gained evidence: %+v %v", got, err)
			}
		})
	}
}

func TestPinnedReadPermissionHasNoUnsupportedSyscallFallback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "regular-twin")
	if err := os.WriteFile(path, []byte("owned fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	original := readPermAt
	t.Cleanup(func() { readPermAt = original })
	for _, unsupported := range []syscall.Errno{syscall.ENOSYS, syscall.EINVAL} {
		readPermAt = func(int) error { return unsupported }
		got, err := permCheck(path, path)
		if !errors.Is(err, unsupported) || got.State != "" {
			t.Fatal("unsupported pinned call gained proof", got, err)
		}
	}
}
