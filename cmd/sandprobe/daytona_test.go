package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestDaytonaPlanAndApprovalPrecedeCredentials(t *testing.T) {
	isolateCanary(t) // HCN-5: nothing of the person's own canary setup reaches the test
	for _, cmd := range []string{"plan", "run"} {
		var out, err bytes.Buffer
		code := run([]string{cmd, "daytona", "-o", "json"}, &out, &err)
		want := 0
		if cmd == "run" {
			want = exitApproval
		}
		if code != want || !strings.Contains(out.String(), "ephemeral") {
			t.Fatalf("approval code=%d", code)
		}
	}
}
