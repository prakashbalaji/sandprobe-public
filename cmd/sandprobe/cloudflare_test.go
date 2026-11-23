package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestCloudflarePlanAndRunRequireNoCredentialsBeforeApproval(t *testing.T) {
	isolateCanary(t) // HCN-5: nothing of the person's own canary setup reaches the test
	for _, args := range [][]string{{"plan", "cloudflare", "-o", "json"}, {"run", "cloudflare", "-o", "json"}} {
		var out, stderr bytes.Buffer
		code := run(args, &out, &stderr)
		want := 0
		if args[0] == "run" {
			want = exitApproval
		}
		if code != want || !strings.Contains(out.String(), "cloudflare") {
			t.Fatalf("approval gate: code=%d out=%s err=%s", code, out.String(), stderr.String())
		}
	}
}

func TestCloudflareNoIntentMakesNoDeletionClaim(t *testing.T) {
	s := cloudflareCleanupEvidence(false)
	if strings.Contains(s, "destruction confirmed") || !strings.Contains(s, "untouched") {
		t.Fatal("false deletion claim")
	}
}
