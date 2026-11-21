//go:build linux

package probe

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
)

// The proc_open twins (TWN-1): two children of the probe's own. One stays dumpable, so its /proc files must open
// through the same call; the other marks itself non-dumpable with prctl, so the kernel must refuse them to a
// non-root probe. Both sides of the twin, through the same mechanism.
const twinEnv = "SANDPROBE_TWIN_CHILD"

func init() {
	mode := os.Getenv(twinEnv)
	if mode == "" {
		return
	}
	if mode == "nodump" {
		syscall.RawSyscall(syscall.SYS_PRCTL, 4 /* PR_SET_DUMPABLE */, 0, 0)
	}
	os.Stdout.Write([]byte{'r'})
	io.Copy(io.Discard, os.Stdin) // wait until the parent closes stdin
	os.Exit(0)
}

type child struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
}

func startChild(mode string) (*child, error) {
	cmd := exec.Command("/proc/self/exe")
	cmd.Env = append(os.Environ(), twinEnv+"="+mode)
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(out, make([]byte, 1)); err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return nil, err
	}
	return &child{cmd, in}, nil
}

func (c *child) pid() int { return c.cmd.Process.Pid }

func (c *child) stop() {
	c.stdin.Close()
	c.cmd.Process.Kill()
	c.cmd.Wait()
}

// twins holds each mechanism's twin, both sides, worked out once in the probe's private scratch directory.
type twins struct {
	dir                     string
	readOK, readRefused     bool // file_read: the probe's own 0600 file opens; its own 0000 file is refused
	writeOK, writeRefused   bool // write_perm: its scratch directory is writable; its own 0500 directory isn't
	permOK, permRefused     bool // read_perm: the same files, by faccessat(R_OK)
	procOK, procRefused     map[string]bool
	children                map[int]bool // the twin children's PIDs, never counted as other processes
	readOnlyDir, ownNoPerms string
}

func makeTwins() (*twins, error) {
	dir, err := os.MkdirTemp("", "sandprobe-") // 0700, removed by close
	if err != nil {
		return nil, err
	}
	tw := &twins{dir: dir, procOK: map[string]bool{}, procRefused: map[string]bool{}, children: map[int]bool{}}
	own := filepath.Join(dir, "own600")
	tw.ownNoPerms = filepath.Join(dir, "own000")
	tw.readOnlyDir = filepath.Join(dir, "ro")
	if err := os.WriteFile(own, []byte("x"), 0o600); err != nil {
		return tw, err
	}
	if err := os.WriteFile(tw.ownNoPerms, []byte("x"), 0o600); err != nil {
		return tw, err
	}
	if err := os.Chmod(tw.ownNoPerms, 0); err != nil {
		return tw, err
	}
	if err := os.Mkdir(tw.readOnlyDir, 0o500); err != nil {
		return tw, err
	}
	if t, _, err := readCheck("twin", own); err == nil {
		tw.readOK = t.State == "found"
	}
	if t, _, err := readCheck("twin", tw.ownNoPerms); err == nil {
		tw.readRefused = t.State == "refused"
	}
	tw.writeOK = syscall.Faccessat(unixAtFDCWD, dir, 2, atEAccess) == nil
	tw.writeRefused = errnoOf(syscall.Faccessat(unixAtFDCWD, tw.readOnlyDir, 2, atEAccess)) == syscall.EACCES
	if t, err := permCheck("twin", own); err == nil {
		tw.permOK = t.State == "found"
	}
	if t, err := permCheck("twin", tw.ownNoPerms); err == nil {
		tw.permRefused = t.State == "refused"
	}

	dump, err := startChild("dump")
	if err != nil {
		return tw, nil // no proc twin: SEC-2 and SEC-5 can't pass, and the grader will say so
	}
	defer dump.stop()
	nodump, err := startChild("nodump")
	if err != nil {
		return tw, nil
	}
	defer nodump.stop()
	tw.children[dump.pid()], tw.children[nodump.pid()] = true, true
	for _, f := range []string{"environ", "mem"} {
		if t, err := procCheck("twin", "/proc/"+strconv.Itoa(dump.pid())+"/"+f); err == nil {
			tw.procOK[f] = t.State == "found"
		}
		if t, err := procCheck("twin", "/proc/"+strconv.Itoa(nodump.pid())+"/"+f); err == nil {
			tw.procRefused[f] = t.State == "refused"
		}
	}
	return tw, nil
}

func (tw *twins) close() {
	os.Chmod(tw.readOnlyDir, 0o700)
	os.Chmod(tw.ownNoPerms, 0o600)
	os.RemoveAll(tw.dir)
}
