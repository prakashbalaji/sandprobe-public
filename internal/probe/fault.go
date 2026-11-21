//go:build linux && sandprobe_faults

package probe

import (
	"os"
	"syscall"
)

// A fault-injection build (Tests, the network fixture): SANDPROBE_FAULT makes connect, for anything but loopback,
// report what a broken or lying client might, without the kernel ever trying. The evidence the probe gathers stays
// honest, so the grader must refuse every one of these as a refusal. Never part of a shipped probe.
func init() {
	fault := os.Getenv("SANDPROBE_FAULT")
	if fault == "" {
		return
	}
	real := sysConnect
	sysConnect = func(fd int, sa syscall.Sockaddr) error {
		if in, ok := sa.(*syscall.SockaddrInet4); ok && in.Addr[0] == 127 {
			return real(fd, sa) // the loopback twin still works: the evidence alone must decide
		}
		switch fault {
		case "skip-refused": // no connect, a refusal reported immediately
			return syscall.ECONNREFUSED
		case "skip-inprogress": // no connect, as if one were under way
			return syscall.EINPROGRESS
		case "prebind-refused": // a local port bound, no connect, a refusal-shaped error
			syscall.Bind(fd, &syscall.SockaddrInet4{})
			return syscall.ECONNREFUSED
		case "hostunreach":
			return syscall.EHOSTUNREACH
		case "eperm": // beside Docker's own seccomp filter, always active in the fixtures
			return syscall.EPERM
		}
		return real(fd, sa)
	}
}
