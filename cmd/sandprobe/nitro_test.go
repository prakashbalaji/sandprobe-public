package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// printedFix returns the command after "fix: " in what a refused command printed on stderr.
func printedFix(t *testing.T, stderr string) string {
	t.Helper()
	for _, line := range strings.Split(stderr, "\n") {
		if fix, ok := strings.CutPrefix(strings.TrimSpace(line), "fix: "); ok {
			return fix
		}
	}
	t.Fatalf("no fix line in %q", stderr)
	return ""
}

// pasteFix runs a printed fix the way a person pastes it into a shell: through sh, in a directory whose
// deploy/<script> holds body, with awsProfile as AWS_PROFILE (unset when nil), and an aws first on PATH that only
// records it was called. It returns the combined output, the exit error, and whether aws was called.
func pasteFix(t *testing.T, fix, script string, body []byte, awsProfile *string) (string, error, bool) {
	t.Helper()
	dir := t.TempDir()
	for _, d := range []string{"deploy", "bin"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	called := filepath.Join(dir, "aws-called")
	for path, b := range map[string][]byte{
		filepath.Join(dir, "deploy", script): body,
		filepath.Join(dir, "bin", "aws"):     []byte("#!/bin/sh\n: >'" + called + "'\nexit 99\n"),
		filepath.Join(dir, "fix.sh"):         []byte(fix + "\n"),
	} {
		if err := os.WriteFile(path, b, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if out, err := exec.Command("sh", "-n", filepath.Join(dir, "fix.sh")).CombinedOutput(); err != nil {
		t.Fatalf("sh -n %q: %v %s", fix, err, out)
	}
	cmd := exec.Command("sh", "-c", fix)
	cmd.Dir, cmd.Env = dir, []string{"HOME=" + dir, "PATH=" + filepath.Join(dir, "bin") + ":/usr/bin:/bin"}
	if awsProfile != nil {
		cmd.Env = append(cmd.Env, "AWS_PROFILE="+*awsProfile)
	}
	out, err := cmd.CombinedOutput()
	_, statErr := os.Stat(called)
	return string(out), err, statErr == nil
}

// fixRunsAsPasted proves a printed deploy-script fix does what it says once pasted, rather than how it's spelled: the
// whole line is a command; AWS_PROFILE's value reaches the script as PROFILE exactly, its quotes shell syntax and
// never data, with the subcommand; and with AWS_PROFILE unset, PROFILE is empty and the real script refuses it before
// its aws is called.
func fixRunsAsPasted(t *testing.T, fix, script, sub string) {
	t.Helper()
	stub := []byte("#!/bin/sh\nprintf '%s|%s\\n' \"$PROFILE\" \"$*\"\n")
	profile := "sandprobe-test-profile"
	if out, err, aws := pasteFix(t, fix, script, stub, &profile); err != nil || aws || out != profile+"|"+sub+"\n" {
		t.Errorf("%q with AWS_PROFILE=%s: %v, aws called %v, the script got %q", fix, profile, err, aws, out)
	}
	if out, err, aws := pasteFix(t, fix, script, stub, nil); err != nil || aws || out != "|"+sub+"\n" {
		t.Errorf("%q with AWS_PROFILE unset: %v, aws called %v, the script got %q, not an empty PROFILE", fix, err, aws, out)
	}
	real, err := os.ReadFile(filepath.Join("..", "..", "deploy", script))
	if err != nil {
		t.Fatal(err)
	}
	if out, err, aws := pasteFix(t, fix, script, real, nil); err == nil || aws || !strings.Contains(out, "set PROFILE") {
		t.Errorf("%q with AWS_PROFILE unset, the real %s: %v, aws called %v, %q", fix, script, err, aws, out)
	}
}

// With no cluster of Sandprobe's own, and with one that isn't whole yet, plan aws-nitro prints a fix that works when
// pasted: deploy/eks.sh needs PROFILE, and the fix hands it AWS_PROFILE's value. providers prints the same fix: it
// takes eksTarget's.
func TestNitroFixNamesProfile(t *testing.T) {
	isolateCanary(t) // its own HOME, so no eks-*.state of this machine's is found
	var out, errs bytes.Buffer
	if code := run([]string{"plan", "aws-nitro"}, &out, &errs); code != exitLogin || !strings.Contains(errs.String(), "no single EKS cluster") {
		t.Fatalf("plan aws-nitro: exit %d, %s", code, errs.String())
	}
	fix := printedFix(t, errs.String())
	fixRunsAsPasted(t, fix, "eks.sh", "up")
	var ce *cliError
	if _, _, err := eksTarget(); !errors.As(err, &ce) || ce.Fix != fix {
		t.Errorf("eksTarget's fix, which providers prints: %v", err)
	}

	if err := os.MkdirAll(configDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir(), "eks-test-us-west-2.state"), []byte("profile=test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	errs.Reset()
	if code := run([]string{"plan", "aws-nitro"}, &out, &errs); code != exitLogin || !strings.Contains(errs.String(), "isn't whole yet") {
		t.Fatalf("plan aws-nitro, a deployment not whole yet: exit %d, %s", code, errs.String())
	}
	fixRunsAsPasted(t, printedFix(t, errs.String()), "eks.sh", "status")
}
