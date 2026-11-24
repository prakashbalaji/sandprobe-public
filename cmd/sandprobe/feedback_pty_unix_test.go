//go:build darwin || linux

package main

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestFeedbackPTYHelper runs the real command inside a child PTY when TestFeedbackPromptGatePTY spawns it.
func TestFeedbackPTYHelper(t *testing.T) {
	if os.Getenv("SANDPROBE_FBK_PTY_HELPER") != "1" {
		return
	}
	if os.Getenv("SANDPROBE_FBK_PTY_OWNED") == "1" { // make this group the PTY's foreground, and check it took
		if err := unix.IoctlSetPointerInt(0, unix.TIOCSPGRP, unix.Getpgrp()); err != nil || !isForegroundTTY(0) {
			os.Exit(98)
		}
	}
	var bg *exec.Cmd
	if os.Getenv("SANDPROBE_FBK_PTY_BACKGROUND") == "1" { // hand the foreground to another group in this session
		bg = exec.Command("/bin/sleep", "30")
		bg.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := bg.Start(); err != nil {
			os.Exit(97)
		}
		if err := unix.IoctlSetPointerInt(0, unix.TIOCSPGRP, bg.Process.Pid); err != nil || isForegroundTTY(0) {
			bg.Process.Kill()
			os.Exit(96)
		}
	}
	code := run([]string{"feedback", "bug", "-title", "pty", "-body-file", os.Getenv("SANDPROBE_FBK_PTY_BODY")}, os.Stdout, os.Stderr)
	if bg != nil {
		bg.Process.Kill()
	}
	os.Exit(code)
}

// FBK-5, AGT-1: the typed yes is asked only through UX-7's gate, over a real PTY: a foreground terminal asks and
// takes only yes; a background process group, a PTY that isn't the session's controlling terminal, CI, TERM=dumb and
// SANDPROBE_NO_KEYS never ask, never block, and end at the preview with its code.
func TestFeedbackPromptGatePTY(t *testing.T) {
	body := writeBody(t, plainBody)
	spawn := func(t *testing.T, owned bool, env ...string) (*exec.Cmd, *os.File, *ptyCollector) {
		t.Helper()
		master, slave, err := openPTY()
		if err != nil {
			t.Fatalf("openPTY: %v", err)
		}
		t.Cleanup(func() { master.Close(); slave.Close() })
		cmd := exec.Command(os.Args[0], "-test.run=^TestFeedbackPTYHelper$")
		cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // a new session: the PTY is its terminal only when owned
		cmd.Env = []string{"PATH=" + t.TempDir(), "HOME=" + t.TempDir(), "TERM=xterm-256color", "CI=", "SANDPROBE_NO_KEYS=",
			"SANDPROBE_FBK_PTY_HELPER=1", "SANDPROBE_FBK_PTY_BODY=" + body}
		if owned {
			cmd.SysProcAttr.Setctty, cmd.SysProcAttr.Ctty = true, 0
			cmd.Env = append(cmd.Env, "SANDPROBE_FBK_PTY_OWNED=1")
		}
		cmd.Env = append(cmd.Env, env...)
		col := &ptyCollector{}
		col.start(master)
		if err := cmd.Start(); err != nil {
			t.Fatalf("start helper: %v", err)
		}
		return cmd, master, col
	}
	wait := func(t *testing.T, cmd *exec.Cmd, col *ptyCollector) int {
		t.Helper()
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				return ee.ExitCode()
			}
			return 0
		case <-time.After(5 * time.Second):
			cmd.Process.Kill()
			t.Fatalf("the command blocked on the PTY:\n%s", col.String())
			return -1
		}
	}

	t.Run("foreground asks, and yes prints the link", func(t *testing.T) {
		cmd, master, col := spawn(t, true)
		waitForSubstring(t, col, "Type yes: ", 4*time.Second)
		master.Write([]byte("yes\n"))
		if code := wait(t, cmd, col); code != exitGraded || !strings.Contains(col.String(), feedbackIssue+"/new?") {
			t.Fatalf("exit %d:\n%s", code, col.String())
		}
	})
	t.Run("foreground takes only yes", func(t *testing.T) {
		cmd, master, col := spawn(t, true)
		waitForSubstring(t, col, "Type yes: ", 4*time.Second)
		master.Write([]byte("y\n"))
		if code := wait(t, cmd, col); code != exitApproval || strings.Contains(col.String(), feedbackIssue+"/new?") {
			t.Fatalf("exit %d:\n%s", code, col.String())
		}
	})
	for name, c := range map[string]struct {
		owned bool
		env   []string
	}{
		"a background process group": {true, []string{"SANDPROBE_FBK_PTY_BACKGROUND=1"}},
		"a PTY it doesn't own":       {false, nil},
		"CI":                         {true, []string{"CI=true"}},
		"TERM=dumb":                  {true, []string{"TERM=dumb"}},
		"SANDPROBE_NO_KEYS":          {true, []string{"SANDPROBE_NO_KEYS=1"}},
	} {
		t.Run(name+" never asks", func(t *testing.T) {
			cmd, _, col := spawn(t, c.owned, c.env...)
			code := wait(t, cmd, col)
			if code != exitApproval || strings.Contains(col.String(), "Type yes") || !strings.Contains(col.String(), "-confirm ") {
				t.Fatalf("exit %d:\n%s", code, col.String())
			}
		})
	}
}
