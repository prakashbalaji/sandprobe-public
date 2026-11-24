//go:build darwin || linux

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestPTYHelperProcess runs inside a real child PTY when spawned by TestPTYKeyLoopIdleEOFSignalsAndOptOut.
func TestPTYHelperProcess(t *testing.T) {
	if os.Getenv("SANDPROBE_PTY_HELPER") != "1" {
		return
	}
	// The PTY is this session's controlling terminal (Setsid and Setctty in spawn). Make this process's group its
	// foreground with tcsetpgrp, and refuse to run unless the fail-closed check agrees, so no case below can reach the
	// key loop through a foreground check that failed open.
	if err := unix.IoctlSetPointerInt(0, unix.TIOCSPGRP, unix.Getpgrp()); err != nil || !isForegroundTTY(0) {
		os.Exit(98)
	}
	var bg *exec.Cmd
	if os.Getenv("SANDPROBE_PTY_BACKGROUND") == "1" { // hand the foreground to another group in this session
		bg = exec.Command("sleep", "30")
		bg.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := bg.Start(); err != nil {
			os.Exit(97)
		}
		if err := unix.IoctlSetPointerInt(0, unix.TIOCSPGRP, bg.Process.Pid); err != nil || isForegroundTTY(0) {
			bg.Process.Kill()
			os.Exit(96)
		}
	}
	vibe := loadReportJSON(t, "../../demo/reports/vibe.json")
	code, err := finish(
		opts{out: "text", stdout: os.Stdout},
		runFlags{outDir: os.Getenv("SANDPROBE_PTY_OUTDIR"), theme: "graphite", min: os.Getenv("SANDPROBE_PTY_MIN")},
		vibe,
		true,
	)
	if err != nil {
		os.Exit(99)
	}
	// Report the terminal's state after the key loop returned: once this session leader exits, macOS revokes its
	// controlling terminal, so the parent can no longer read it.
	state := "unreadable"
	if cooked, err := isCookedTTY(0); err == nil && cooked {
		state = "cooked"
	} else if err == nil {
		state = "raw"
	}
	fmt.Printf("\r\nTERMIOS:%s\r\n", state)
	if bg != nil {
		bg.Process.Kill()
	}
	os.Exit(code)
}

type ptyCollector struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *ptyCollector) start(r *os.File) {
	go func() {
		tmp := make([]byte, 1024)
		for {
			n, err := r.Read(tmp)
			if n > 0 {
				c.mu.Lock()
				c.buf.Write(tmp[:n])
				c.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
}

func (c *ptyCollector) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

func waitForSubstring(t *testing.T, col *ptyCollector, sub string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(col.String(), sub) {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %q in PTY output:\n%s", sub, col.String())
}

// UX-7, AGT-1: exercises finish() + interactResult() over a real OS PTY across silent open stdin,
// q, EOF, SIGTERM, SIGHUP, CI=true, and SANDPROBE_NO_KEYS=1, verifying bounded completion and cooked termios restoration.
func TestPTYKeyLoopIdleEOFSignalsAndOptOut(t *testing.T) {
	spawn := func(t *testing.T, extraEnv ...string) (*exec.Cmd, *os.File, *os.File, *ptyCollector) {
		t.Helper()
		master, slave, err := openPTY()
		if err != nil {
			t.Fatalf("openPTY: %v", err)
		}
		t.Cleanup(func() {
			_ = master.Close()
			_ = slave.Close()
		})
		cmd := exec.Command(os.Args[0], "-test.run=^TestPTYHelperProcess$")
		cmd.Stdin = slave
		cmd.Stdout = slave
		cmd.Stderr = slave
		// A session leader whose controlling terminal is the PTY (child fd 0), as an interactive shell's job would be.
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
		env := []string{
			"PATH=" + os.Getenv("PATH"),
			"HOME=" + t.TempDir(),
			"TERM=xterm-256color",
			"NO_COLOR=1",
			"CI=",
			"SANDPROBE_NO_KEYS=",
			"SANDPROBE_PTY_HELPER=1",
			"SANDPROBE_PTY_OUTDIR=" + t.TempDir(),
		}
		cmd.Env = append(env, extraEnv...)
		col := &ptyCollector{}
		col.start(master)
		if err := cmd.Start(); err != nil {
			t.Fatalf("start helper: %v", err)
		}
		return cmd, master, slave, col
	}

	waitExit := func(t *testing.T, cmd *exec.Cmd, timeout time.Duration) int {
		t.Helper()
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			if err == nil {
				return 0
			}
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				return ee.ExitCode()
			}
			t.Fatalf("unexpected wait error: %v", err)
			return -1
		case <-time.After(timeout):
			_ = cmd.Process.Kill()
			t.Fatalf("child hung on PTY beyond %s", timeout)
			return -1
		}
	}

	// restored checks the helper's own report of its terminal after the key loop returned.
	restored := func(t *testing.T, col *ptyCollector, after string) {
		t.Helper()
		waitForSubstring(t, col, "TERMIOS:", 2*time.Second)
		if !strings.Contains(col.String(), "TERMIOS:cooked") {
			t.Fatalf("PTY not cooked after %s:\n%s", after, col.String())
		}
	}

	t.Run("silent open stdin auto-exits with OUT-4 exit code and restores termios", func(t *testing.T) {
		cmd, _, _, col := spawn(t, "SANDPROBE_KEY_IDLE_MS=180", "SANDPROBE_PTY_MIN=5")
		code := waitExit(t, cmd, 4*time.Second)
		if code != exitBelowMin {
			t.Fatalf("exit code = %d, want %d; output:\n%s", code, exitBelowMin, col.String())
		}
		if !strings.Contains(col.String(), "Idle timeout; exiting.") {
			t.Fatalf("missing idle timeout notice:\n%s", col.String())
		}
		restored(t, col, "idle exit")
	})

	t.Run("q exits and restores termios", func(t *testing.T) {
		cmd, master, slave, col := spawn(t, "SANDPROBE_KEY_IDLE_MS=8000")
		waitForSubstring(t, col, "[q] quit", 4*time.Second)
		if cooked, err := isCookedTTY(int(slave.Fd())); err != nil || cooked {
			t.Fatalf("expected raw mode while key bar active (cooked=%v err=%v)", cooked, err)
		}
		_, _ = master.Write([]byte("q"))
		if code := waitExit(t, cmd, 3*time.Second); code != exitGraded {
			t.Fatalf("exit code = %d, want 0", code)
		}
		restored(t, col, "q")
	})

	t.Run("a background process group skips the key loop", func(t *testing.T) {
		cmd, _, _, col := spawn(t, "SANDPROBE_KEY_IDLE_MS=10000", "SANDPROBE_PTY_BACKGROUND=1")
		if code := waitExit(t, cmd, 3*time.Second); code != exitGraded {
			t.Fatalf("exit code = %d, want 0 well inside the 10 s idle bound; output:\n%s", code, col.String())
		}
		waitForSubstring(t, col, "Report", 2*time.Second)
		if s := col.String(); !strings.Contains(s, "SCORE 1/6") || strings.Contains(s, "[q] quit") {
			t.Fatalf("a background job showed the key bar or no summary:\n%s", s)
		}
	})

	t.Run("Ctrl-D EOF key exits and restores termios", func(t *testing.T) {
		cmd, master, _, col := spawn(t, "SANDPROBE_KEY_IDLE_MS=8000")
		waitForSubstring(t, col, "[q] quit", 4*time.Second)
		_, _ = master.Write([]byte{0x04})
		if code := waitExit(t, cmd, 3*time.Second); code != exitGraded {
			t.Fatalf("exit code = %d, want 0", code)
		}
		restored(t, col, "Ctrl-D")
	})

	t.Run("EOF on master close exits and restores termios", func(t *testing.T) {
		cmd, master, _, col := spawn(t, "SANDPROBE_KEY_IDLE_MS=8000")
		waitForSubstring(t, col, "[q] quit", 4*time.Second)
		_ = master.Close()
		if code := waitExit(t, cmd, 3*time.Second); code != exitGraded {
			t.Fatalf("exit code = %d, want 0", code)
		}
		// With its master closed the PTY is hung up, so there is no terminal left to restore or read: the bounded
		// exit above is what this case proves.
	})

	for _, sigCase := range []struct {
		name string
		sig  syscall.Signal
	}{
		{"SIGTERM", syscall.SIGTERM},
		{"SIGHUP", syscall.SIGHUP},
	} {
		t.Run(sigCase.name+" restores termios", func(t *testing.T) {
			cmd, _, slave, col := spawn(t, "SANDPROBE_KEY_IDLE_MS=10000")
			waitForSubstring(t, col, "[q] quit", 4*time.Second)
			if cooked, err := isCookedTTY(int(slave.Fd())); err != nil || cooked {
				t.Fatalf("expected raw mode before %s (cooked=%v err=%v)", sigCase.name, cooked, err)
			}
			if err := cmd.Process.Signal(sigCase.sig); err != nil {
				t.Fatalf("signal %s: %v", sigCase.name, err)
			}
			_ = waitExit(t, cmd, 3*time.Second)
			restored(t, col, sigCase.name)
		})
	}

	for _, envOpt := range []string{"CI=true", "SANDPROBE_NO_KEYS=1"} {
		t.Run(envOpt+" skips key loop immediately", func(t *testing.T) {
			start := time.Now()
			cmd, _, _, col := spawn(t, "SANDPROBE_KEY_IDLE_MS=10000", envOpt)
			if code := waitExit(t, cmd, 3*time.Second); code != exitGraded {
				t.Fatalf("%s exit = %d, want 0", envOpt, code)
			}
			if elapsed := time.Since(start); elapsed > 2*time.Second {
				t.Fatalf("%s waited %s", envOpt, elapsed)
			}
			if strings.Contains(col.String(), "[Enter] walk") {
				t.Fatalf("%s entered interactive key bar:\n%s", envOpt, col.String())
			}
			restored(t, col, envOpt)
		})
	}
}

// UX-7, AGT-1: foreground detection fails closed. A pipe (ENOTTY) and a PTY that isn't this process's controlling
// terminal both read as not foreground, so neither can enter the key loop.
func TestForegroundFailsClosed(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if isForegroundTTY(int(r.Fd())) {
		t.Error("a pipe reads as a foreground terminal")
	}
	master, slave, err := openPTY()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer slave.Close()
	if isForegroundTTY(int(slave.Fd())) {
		t.Error("a PTY that isn't this process's controlling terminal reads as foreground")
	}
}
