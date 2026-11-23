//go:build linux

package probe

import (
	"errors"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The runtime's fork hooks, which the syscall package's own fork uses: before the fork they block signals and make
// any stack growth fail loudly; after it the parent undoes that, and the child resets its signal handlers. Go keeps
// them for code outside the standard library that forks for itself (go.dev/issue/67401).
//
//go:linkname runtimeBeforeFork syscall.runtime_BeforeFork
func runtimeBeforeFork()

//go:linkname runtimeAfterFork syscall.runtime_AfterFork
func runtimeAfterFork()

//go:linkname runtimeAfterForkInChild syscall.runtime_AfterForkInChild
func runtimeAfterForkInChild()

const atEmptyPath = 0x1000 // AT_EMPTY_PATH

// spawnFD starts the file the descriptor fd holds as a child in a process group of its own, with argv, env, and
// stdio as its standard input, output and error (AMP-1). It runs it with execveat(fd, "", AT_EMPTY_PATH): no path is
// looked up, so nothing mounted over /proc, or anywhere else, can stand in for the pinned file. Keep fd close-on-exec:
// a #! script then fails with ENOENT rather than handing its interpreter a /dev/fd path to look up. A failed exec
// returns its errno. A child that dies before the exec looks like one that ran, so its caller treats a run ended by a
// signal as unknown.
func spawnFD(fd int, argv, env []string, stdio [3]int) (int, error) {
	for _, f := range append(stdio[:], fd) {
		if f < 3 {
			return 0, errors.New("a descriptor below 3 would be overwritten in the child")
		}
	}
	argvp, err := syscall.SlicePtrFromStrings(argv)
	if err != nil {
		return 0, err
	}
	envp, err := syscall.SlicePtrFromStrings(env)
	if err != nil {
		return 0, err
	}
	empty, _ := syscall.BytePtrFromString("")
	var p [2]int // the child writes its errno here if the exec fails; a successful exec closes it
	if err := syscall.Pipe2(p[:], syscall.O_CLOEXEC); err != nil {
		return 0, err
	}
	syscall.ForkLock.Lock()
	pid, errno := forkExecveat(uintptr(fd), &argvp[0], &envp[0], empty, stdio, p[1])
	syscall.ForkLock.Unlock()
	syscall.Close(p[1])
	defer syscall.Close(p[0])
	if errno != 0 {
		return 0, errno
	}
	var e syscall.Errno
	buf := (*[unsafe.Sizeof(e)]byte)(unsafe.Pointer(&e))
	n := 0
	for n < len(buf) {
		m, err := syscall.Read(p[0], buf[n:])
		if err == syscall.EINTR {
			continue
		}
		if m <= 0 {
			break
		}
		n += m
	}
	if n == 0 {
		return pid, nil // the pipe closed on exec
	}
	var ws syscall.WaitStatus
	for {
		if _, err := syscall.Wait4(pid, &ws, 0, nil); err != syscall.EINTR {
			break
		}
	}
	if n != len(buf) {
		return 0, errors.New("the child's exec error came back short")
	}
	return 0, e
}

// forkExecveat is the fork and, in the child, everything up to the exec. Between the two the child does only raw
// system calls, on values computed before the fork, as the syscall package's forkAndExecInChild does: no allocation,
// no stack growth, no Go runtime.
//
//go:norace
//go:nocheckptr
func forkExecveat(fd uintptr, argv, env **byte, path *byte, stdio [3]int, errw int) (pid int, err syscall.Errno) {
	argvp, envp, pathp := uintptr(unsafe.Pointer(argv)), uintptr(unsafe.Pointer(env)), uintptr(unsafe.Pointer(path))
	in, out, errout := uintptr(stdio[0]), uintptr(stdio[1]), uintptr(stdio[2])
	runtimeBeforeFork()
	r1, _, e := syscall.RawSyscall6(syscall.SYS_CLONE, uintptr(syscall.SIGCHLD), 0, 0, 0, 0, 0)
	if e != 0 || r1 != 0 {
		runtimeAfterFork()
		return int(r1), e
	}
	// The child.
	runtimeAfterForkInChild()
	if _, _, e = syscall.RawSyscall(syscall.SYS_SETPGID, 0, 0, 0); e == 0 {
		if _, _, e = syscall.RawSyscall(syscall.SYS_DUP3, in, 0, 0); e == 0 {
			if _, _, e = syscall.RawSyscall(syscall.SYS_DUP3, out, 1, 0); e == 0 {
				if _, _, e = syscall.RawSyscall(syscall.SYS_DUP3, errout, 2, 0); e == 0 {
					_, _, e = syscall.RawSyscall6(unix.SYS_EXECVEAT, fd, pathp, argvp, envp, atEmptyPath, 0)
				}
			}
		}
	}
	syscall.RawSyscall(syscall.SYS_WRITE, uintptr(errw), uintptr(unsafe.Pointer(&e)), unsafe.Sizeof(e))
	for {
		syscall.RawSyscall(syscall.SYS_EXIT_GROUP, 253, 0, 0)
	}
}
