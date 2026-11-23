package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// The Sprites plan names no Fly-owned endpoint: no metadata address, and the box-named destinations are excluded.
func TestSpritesPlanContactsOnlyTheCanary(t *testing.T) {
	var out bytes.Buffer
	printPlan(&out, sprPlan("example-org", hostedChoice(t), runFlags{allowLocalProxy: true}, ""))
	text := out.String()
	for _, bad := range []string{"169.254.", "Kubernetes API the agent's environment names", "yes: EGR-3"} {
		if strings.Contains(text, bad) {
			t.Errorf("the Sprites plan still names %q", bad)
		}
	}
	for _, want := range []string{"SEC-4, EGR-3, AMP-6 and AMP-7 are excluded", "excluded even with -allow-local-proxy"} {
		if !strings.Contains(text, want) {
			t.Errorf("the Sprites plan doesn't say %q", want)
		}
	}
}

// -allow-local-proxy asks for EGR-3, which Sprites always excludes, so it's refused before anything else happens.
func TestSpritesRefusesAllowLocalProxy(t *testing.T) {
	r := runFlags{allowLocalProxy: true}
	_, _, err := r.resolve()
	if ce, ok := err.(*cliError); !ok || !strings.Contains(ce.Error(), "no effect on Sprites") {
		t.Fatalf("want a usage refusal, got %v", err)
	}
}

// SPR-1 and SPR-2: the approval names the setup script by its SHA-256, how it runs, the launcher it may leave, and
// where the probe goes; a plan without -setup mentions none of that.
func TestSpritesPlanNamesTheSetup(t *testing.T) {
	c := hostedChoice(t)
	sum := strings.Repeat("ab", 32)
	var with, without bytes.Buffer
	printPlan(&with, sprPlan("example-org", c, runFlags{setup: "/home/me/setup.sh"}, sum))
	printPlan(&without, sprPlan("example-org", c, runFlags{}, ""))
	for _, want := range []string{"setup.sh (sha256 " + sum + ")", "sh -s", "nothing it prints is kept", "/usr/local/bin/agent-exec", "/var/tmp/sandprobe-"} {
		if !strings.Contains(with.String(), want) {
			t.Errorf("the plan with -setup doesn't say %q", want)
		}
	}
	if strings.Contains(without.String(), "setup") || strings.Contains(without.String(), "agent-exec") || !strings.Contains(without.String(), "/var/tmp/sandprobe-") {
		t.Errorf("the plan without -setup: %s", without.String())
	}
}

// The setup script is read through its bound, never from a pipe or device, and never empty.
func TestReadSetupBounds(t *testing.T) {
	dir := t.TempDir()
	ok := filepath.Join(dir, "ok.sh")
	os.WriteFile(ok, []byte("true\n"), 0o600)
	if b, sum, err := readSetup(ok); err != nil || string(b) != "true\n" || len(sum) != 64 {
		t.Fatalf("%q %q %v", b, sum, err)
	}
	big := filepath.Join(dir, "big.sh")
	os.WriteFile(big, bytes.Repeat([]byte("#"), 256<<10+1), 0o600)
	empty := filepath.Join(dir, "empty.sh")
	os.WriteFile(empty, nil, 0o600)
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{big, empty, fifo, dir, filepath.Join(dir, "missing")} {
		if _, _, err := readSetup(p); err == nil {
			t.Errorf("%s was read", filepath.Base(p))
		}
	}
}
