//go:build linux

package probe

import (
	"bytes"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// WrapFailed is the end-marker status when the wrapper can't start the run: nothing ran, nothing is graded (LNC-2).
const WrapFailed = 96

// Wrap is run exec's wrapper mode (LNC-1, LNC-2): the shell has replaced itself with this process, so no shell is left
// for SEC-2 or SEC-5 to count. It takes the run's token and the scratch's owner token from its stdin's first line,
// never its command line, prints the start marker, starts the run from its own executable with its own environment
// passed through entry for entry (adding only SANDPROBE_TWIN=1, when no entry has that name), passes TERM, INT and HUP
// on to it, removes the scratch only when it carries the owner's mark, and only then prints the end marker with the
// run's status. It reads nothing but that line, its own environment and the owner mark, and runs no check.
func Wrap(scratch string, runArgs []string) int { return wrapFrom("/proc/self/exe", scratch, runArgs) }

// HeaderLen is LNC-1's first line of the input file: the token, a space, the owner and a newline.
const HeaderLen = 50

func wrapFrom(exe, scratch string, runArgs []string) int {
	token, owner, ok := readHeader(os.Stdin)
	if !ok { // nothing printed, nothing removed: the host finds no frame, and confirm-gone removes the scratch
		os.Stderr.WriteString("sandprobe-probe: -wrap needs the token and owner line on its stdin\n")
		return 1
	}
	return wrap(exe, token, scratch, owner, runArgs)
}

// readHeader takes exactly HeaderLen bytes, with no buffering, so the run gets the rest of the same stdin.
func readHeader(f *os.File) (token, owner string, ok bool) {
	b := make([]byte, HeaderLen)
	if _, err := io.ReadFull(f, b); err != nil || b[24] != ' ' || b[49] != '\n' || !lowerHex(b[:24]) || !lowerHex(b[25:49]) {
		return "", "", false
	}
	return string(b[:24]), string(b[25:49]), true
}

func lowerHex(b []byte) bool {
	for _, c := range b {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func wrap(exe, token, scratch, owner string, runArgs []string) int {
	os.Stdout.WriteString("SP-START-" + token + "\n")
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP) // before the run starts, so none is lost
	status := WrapFailed
	if env, err := ownEnviron(); err == nil {
		attr := &os.ProcAttr{Env: env, Files: []*os.File{os.Stdin, os.Stdout, os.Stderr}}
		if run, err := os.StartProcess(exe, append([]string{os.Args[0]}, runArgs...), attr); err == nil {
			done := make(chan struct{})
			go func() {
				for {
					select {
					case s := <-signals:
						run.Signal(s)
					case <-done:
						return
					}
				}
			}()
			st, err := run.Wait()
			close(done)
			if err == nil {
				status = runStatus(st)
			}
		}
	}
	signal.Ignore(syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGPIPE) // the cleanup and the marker finish
	removeOwned(scratch, owner)                                                     // before the end marker: a closed stdout can't skip it
	os.Stdout.WriteString("\nSP-END-" + token + " " + strconv.Itoa(status) + "\n")
	return 0
}

// ownEnviron is this process's environment exactly as exec gave it, from /proc/self/environ: every entry, in order,
// duplicates, entries without "=" and empty entries kept. SANDPROBE_TWIN=1 is added only when no entry has that name.
func ownEnviron() ([]string, error) {
	b, err := os.ReadFile("/proc/self/environ")
	if err != nil {
		return nil, err
	}
	env := []string{}
	if len(b) > 0 {
		env = strings.Split(string(bytes.TrimSuffix(b, []byte{0})), "\x00")
	}
	for _, kv := range env {
		if name, _, _ := strings.Cut(kv, "="); name == "SANDPROBE_TWIN" {
			return env, nil
		}
	}
	return append(env, "SANDPROBE_TWIN=1"), nil
}

// runStatus is the run's exit code, or 128 plus the signal that ended it, as a shell reports it.
func runStatus(st *os.ProcessState) int {
	if ws, ok := st.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return st.ExitCode()
}

// removeOwned removes the scratch only when PRV-15's ownership test holds: a real directory, not a link, whose
// .sp-owner holds the owner token. Anything else at the path is left alone.
func removeOwned(scratch, owner string) {
	if fi, err := os.Lstat(scratch); err != nil || !fi.IsDir() {
		return
	}
	f, err := os.OpenFile(filepath.Join(scratch, ".sp-owner"), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return
	}
	mark, err := io.ReadAll(io.LimitReader(f, 64))
	f.Close()
	if err == nil && strings.TrimRight(string(mark), "\n") == owner {
		os.RemoveAll(scratch)
	}
}

// parentPin is LNC-3: the probe's direct parent, pinned by an O_PATH descriptor on its /proc directory, so a later
// look is at that process and never at whatever holds its PID afterwards, with the device and inode of the file it
// runs.
type parentPin struct {
	pid      int
	dir      int
	dev, ino uint64
}

// pinWrapper pins the probe's direct parent when the kernel shows it runs the probe's own file: the same device and
// inode as /proc/self/exe. Anything else, an error included, pins nothing, and the parent is counted as before.
func pinWrapper() *parentPin { return pinParent(os.Getppid()) }

// pinParent pins ppid only while it is the probe's parent, read again after the descriptor is open, so the pinned
// /proc entry is that process and no other.
func pinParent(ppid int) *parentPin {
	var self unix.Stat_t
	if ppid <= 0 || unix.Stat("/proc/self/exe", &self) != nil {
		return nil
	}
	dir, err := unix.Open("/proc/"+strconv.Itoa(ppid), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil
	}
	var st unix.Stat_t
	if unix.Fstatat(dir, "exe", &st, 0) != nil || st.Dev != self.Dev || st.Ino != self.Ino || os.Getppid() != ppid {
		unix.Close(dir)
		return nil
	}
	return &parentPin{pid: ppid, dir: dir, dev: st.Dev, ino: st.Ino}
}

// holds is LNC-3's second check: the parent is still the probe's parent, alive, and still runs the same file, and so
// does the probe. A parent that died, exec'd another file or whose PID was reused fails it.
func (p *parentPin) holds() bool {
	var st, self unix.Stat_t
	return os.Getppid() == p.pid && unix.Fstatat(p.dir, "exe", &st, 0) == nil && st.Dev == p.dev && st.Ino == p.ino &&
		unix.Stat("/proc/self/exe", &self) == nil && self.Dev == p.dev && self.Ino == p.ino
}
