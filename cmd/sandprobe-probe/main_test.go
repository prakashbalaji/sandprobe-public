//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"sandprobe/internal/obs"
	"strings"
	"testing"
	"time"
)

func TestHostInputFraming(t *testing.T) {
	for _, s := range []string{`{"run_id":"a","Run_ID":"b"}`, `{} {}`, `{"unknown":1}`, `{}` + strings.Repeat(" ", obs.MaxDoc)} {
		var in obs.Input
		if readFrom(strings.NewReader(s), &in) == nil {
			t.Fatal("accepted ambiguous/oversized host input")
		}
	}
	var in obs.Input
	if err := readFrom(strings.NewReader(`{"run_id":"r1"}`), &in); err != nil || in.RunID != "r1" {
		t.Fatal("canonical input rejected")
	}
}
func TestProbeArguments(t *testing.T) {
	for _, args := range [][]string{{"-survey", "extra"}, {"unknown"}, {"", "extra"}, {"-idle", "extra"}} {
		if _, err := parseMode(args); err == nil {
			t.Fatal("extra arguments accepted")
		}
	}
	for _, args := range [][]string{nil, {"-survey"}, {"-mark"}, {"-recheck"}, {"-receiver"}, {"-quick"}, {"-quick", "/tmp"}, {"-idle"}} {
		if _, err := parseMode(args); err != nil {
			t.Fatal(err)
		}
	}
	// LNC-2: -wrap takes exactly the scratch path and -expect-uid N, in their forms; the tokens never come as
	// arguments (LNC-1), and -wrap is never a mode after -expect-uid.
	const tok, scratch = "0123456789abcdef01234567", "/tmp/sandprobe-0123456789abcdef01234567"
	if w, err := parseWrap([]string{"-wrap", scratch, "-expect-uid", "1000"}); err != nil || strings.Join(w, " ") != scratch+" -expect-uid 1000" {
		t.Fatalf("a well-formed -wrap refused: %v %v", w, err)
	}
	for _, args := range [][]string{
		{"-wrap"}, {"-wrap", scratch}, {"-wrap", scratch, "-expect-uid"}, {"-wrap", scratch, "-expect-uid", "x"},
		{"-wrap", scratch, "-expect-uid", "1000", "-survey"}, {"-wrap", scratch, "-survey", "1000"},
		{"-wrap", tok, scratch, "-expect-uid", "1000"}, {"-wrap", scratch, tok, "-expect-uid", "1000"},
		{"-wrap", "/tmp/other", "-expect-uid", "1000"}, {"-wrap", "/tmp/../sandprobe-0123456789abcdef01234567", "-expect-uid", "1000"},
		{"-wrap", "relative/sandprobe-0123456789abcdef01234567", "-expect-uid", "1000"},
		{"-wrap", "/tmp/sandprobe-0123456789ABCDEF01234567", "-expect-uid", "1000"},
		{"-wrap", scratch, "-expect-uid", "1000", "-expect-uid", "1000"},
	} {
		if _, err := parseWrap(args); err == nil {
			t.Errorf("%q accepted", args)
		}
	}
	for _, args := range [][]string{{"-wrap", scratch, "-expect-uid", "1000"}, {"-expect-uid", "1000", "-wrap", scratch}} {
		if _, err := parseMode(args); err == nil {
			t.Errorf("%q accepted as a mode", args)
		}
	}
	if _, rest, _, err := parseExpect([]string{"-expect-uid", "1000", "-wrap", scratch}); err == nil {
		if _, err := parseMode(rest); err == nil {
			t.Error("-wrap accepted after -expect-uid")
		}
	}
}

func TestQuickWatchdog(t *testing.T) {
	if os.Getenv("SANDPROBE_WATCHDOG_HELPER") == "1" {
		quickDeadline(50 * time.Millisecond)
		b := make([]byte, 1<<20)
		for {
			_, _ = os.Stderr.Write(b)
		}
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestQuickWatchdog$")
	cmd.Env = []string{"SANDPROBE_WATCHDOG_HELPER=1"}
	cmd.Stderr = w
	err = cmd.Run()
	if ctx.Err() != nil {
		t.Fatal("watchdog blocked on stderr")
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 5 {
		t.Fatal("watchdog failed to terminate with partial status")
	}
}

// PRV-15: -expect-uid binds every probe run and nothing else; -whoami takes at most one plain user name.
func TestExpectAndWhoAmIArguments(t *testing.T) {
	for _, args := range [][]string{{"-expect-uid"}, {"-expect-uid", "x"}, {"-expect-uid", "-1"}, {"-expect-uid", "99999999999"},
		{"-expect-uid", "1000", "-whoami"}, {"-expect-uid", "1000", "-quick"}, {"-expect-uid", "1", "-expect-uid", "2"}} {
		if _, _, _, err := parseExpect(args); err == nil {
			t.Errorf("%q accepted", args)
		}
	}
	for _, tc := range []struct {
		args []string
		want int
		rest []string
	}{{[]string{"-expect-uid", "1000", "-survey"}, 1000, []string{"-survey"}}, {[]string{"-expect-uid", "0"}, 0, []string{}}} {
		n, rest, bound, err := parseExpect(tc.args)
		if err != nil || !bound || n != tc.want || len(rest) != len(tc.rest) {
			t.Errorf("%q: %d %q %v %v", tc.args, n, rest, bound, err)
		}
	}
	if _, rest, bound, _ := parseExpect([]string{"-survey"}); bound || len(rest) != 1 {
		t.Error("an unbound run was bound")
	}
	for _, args := range [][]string{{"-whoami"}, {"-whoami", "agent"}, {"-whoami", "1000"}} {
		if m, err := parseMode(args); err != nil || m != "-whoami" {
			t.Errorf("%q: %v", args, err)
		}
	}
	for _, args := range [][]string{{"-whoami", "Agent;rm"}, {"-whoami", "a", "b"}, {"-whoami", ""}} {
		if _, err := parseMode(args); err == nil {
			t.Errorf("%q accepted", args)
		}
	}
}

// DKR-1: -idle, run as a box's entrypoint, writes nothing and stays up until it is killed.
func TestIdleStaysUp(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestIdleHelper$")
	cmd.Env = append(os.Environ(), "SANDPROBE_IDLE_HELPER=1")
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		t.Fatalf("-idle returned: %v %q", err, out.String())
	case <-time.After(time.Second):
	}
	cmd.Process.Kill()
	<-done
	if out.Len() != 0 {
		t.Errorf("-idle wrote %q", out.String())
	}
}

// TestIdleHelper is the process TestIdleStaysUp starts: the probe's main with -idle.
func TestIdleHelper(t *testing.T) {
	if os.Getenv("SANDPROBE_IDLE_HELPER") == "" {
		t.Skip("run by TestIdleStaysUp")
	}
	os.Args = []string{"sandprobe-probe", "-idle"}
	main()
}
