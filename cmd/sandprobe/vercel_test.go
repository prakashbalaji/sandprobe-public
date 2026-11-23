package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestVercelPlanDoesNotNeedCredentialsCanaryOrSDK(t *testing.T) {
	isolateCanary(t) // HCN-5: nothing of the person's own canary setup reaches the test
	t.Setenv("SANDPROBE_VERCEL_KEY_FILE", "/does/not/exist")
	t.Setenv("SANDPROBE_VERCEL_PYTHON", "/does/not/exist")
	t.Setenv("SANDPROBE_CANARY", "/does/not/exist")
	var out, errs bytes.Buffer
	code := run([]string{"plan", "vercel", "-o", "json"}, &out, &errs)
	var p planDoc
	if code != 0 || json.Unmarshal(out.Bytes(), &p) != nil || p.Provider != "vercel" {
		t.Fatal("offline plan failed", code, errs.String())
	}
	for _, s := range []string{"900000ms", "no injected secrets", "no volumes"} {
		text := strings.Join(p.Creates, " ") + " " + p.Residual
		if s == "no volumes" {
			s = "snapshots or drives"
		}
		if !strings.Contains(text, s) {
			t.Error("missing scope", s)
		}
	}
	out.Reset()
	errs.Reset()
	code = run([]string{"run", "vercel", "-o", "json"}, &out, &errs)
	if code != exitApproval || !strings.Contains(out.String(), `"needs_approval": true`) {
		t.Fatal("approval did not precede credential/SDK checks", code, errs.String())
	}
}

type vercelCleanupFake struct {
	err    error
	called bool
}

func (f *vercelCleanupFake) Destroy(ctx context.Context) error {
	f.called = true
	if ctx.Err() != nil {
		return errors.New("cleanup inherited cancellation")
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > 3*time.Minute {
		return errors.New("cleanup lacks bounded deadline")
	}
	return f.err
}
func TestVercelCleanupUsesIndependentBoundedContext(t *testing.T) {
	f := &vercelCleanupFake{}
	if err := deleteVercel(f); err != nil || !f.called {
		t.Fatal(err)
	}
	f.err = errors.New("delete refused")
	if err := deleteVercel(f); err == nil {
		t.Fatal("cleanup error ignored")
	}
}
