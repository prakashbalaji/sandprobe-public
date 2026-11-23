package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// With no cluster of Sandprobe's own, plan aws-nitro names the command that makes one with the PROFILE deploy/eks.sh
// needs, since without it the script stops before anything. The fix runs as pasted: no <placeholder> for the shell
// to read as a redirection. providers prints the same fix: it takes eksTarget's.
func TestNitroFixNamesProfile(t *testing.T) {
	isolateCanary(t) // its own HOME, so no eks-*.state of this machine's is found
	want := `PROFILE="$AWS_PROFILE" deploy/eks.sh up`
	var out, errs bytes.Buffer
	if code := run([]string{"plan", "aws-nitro"}, &out, &errs); code != exitLogin || !strings.Contains(errs.String(), "fix: "+want+"\n") {
		t.Errorf("plan aws-nitro: exit %d, %s", code, errs.String())
	}
	var ce *cliError
	if _, _, err := eksTarget(); !errors.As(err, &ce) || ce.Fix != want {
		t.Errorf("eksTarget's fix: %v", err)
	}
}
