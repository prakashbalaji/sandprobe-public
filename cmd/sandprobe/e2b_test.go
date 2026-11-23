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

func TestE2BPlanDoesNotNeedCredentialsCanaryOrSDK(t *testing.T) {
	isolateCanary(t) // HCN-5: nothing of the person's own canary setup reaches the test
	t.Setenv("SANDPROBE_E2B_KEY_FILE", "/does/not/exist")
	t.Setenv("SANDPROBE_E2B_PYTHON", "/does/not/exist")
	t.Setenv("SANDPROBE_CANARY", "/does/not/exist")
	var out, errs bytes.Buffer
	code := run([]string{"plan", "e2b", "-o", "json"}, &out, &errs)
	var p planDoc
	if code != 0 || json.Unmarshal(out.Bytes(), &p) != nil || p.Provider != "e2b" {
		t.Fatal("offline plan failed", code, errs.String())
	}
	for _, s := range []string{"900-second", "no injected secrets", "no volumes"} {
		text := strings.Join(p.Creates, " ") + " " + p.Residual
		if s == "no volumes" {
			s = "volumes or previews"
		}
		if !strings.Contains(text, s) {
			t.Error("missing scope", s)
		}
	}
	out.Reset()
	errs.Reset()
	code = run([]string{"run", "e2b", "-o", "json"}, &out, &errs)
	if code != exitApproval || !strings.Contains(out.String(), `"needs_approval": true`) {
		t.Fatal("approval did not precede credential/SDK checks", code, errs.String())
	}
}

type e2bCleanupFake struct {
	err    error
	called bool
}

func (f *e2bCleanupFake) Destroy(ctx context.Context) error {
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
func TestE2BCleanupUsesIndependentBoundedContext(t *testing.T) {
	f := &e2bCleanupFake{}
	if err := deleteE2B(f); err != nil || !f.called {
		t.Fatal(err)
	}
	f.err = errors.New("delete refused")
	if err := deleteE2B(f); err == nil {
		t.Fatal("cleanup error ignored")
	}
}
