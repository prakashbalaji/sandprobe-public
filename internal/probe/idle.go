//go:build linux

package probe

import (
	"os"
	"os/signal"
	"syscall"
)

// Idle is DKR-1: Sandprobe's own idle process, the container's entrypoint under run docker, so the image's own
// entrypoint and command never run. It reads nothing, writes nothing, opens nothing and starts nothing. As the
// container's init it reaps any orphan the kernel hands it, and it never returns.
func Idle() {
	child := make(chan os.Signal, 1)
	signal.Notify(child, syscall.SIGCHLD)
	for {
		for {
			var ws syscall.WaitStatus
			if pid, err := syscall.Wait4(-1, &ws, syscall.WNOHANG, nil); pid <= 0 || err != nil {
				break
			}
		}
		<-child
	}
}
