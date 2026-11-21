package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestExedevPlanAndApprovalPrecedeCredentials(t *testing.T) {
	for _, cmd := range []string{"plan", "run"} {
		var out, err bytes.Buffer
		code := run([]string{cmd, "exe.dev", "-o", "json"}, &out, &err)
		want := 0
		if cmd == "run" {
			want = exitApproval
		}
		if code != want || !strings.Contains(out.String(), "NO provider-enforced expiry") {
			t.Fatalf("plan/approval failed code=%d", code)
		}
	}
}

type exedevInterruptedCleanup struct {
	parent  context.Context
	called  bool
	failure error
}

func (f *exedevInterruptedCleanup) Destroy(ctx context.Context) error {
	f.called = true
	if f.parent.Err() != context.Canceled {
		return errors.New("test run was not interrupted")
	}
	if ctx.Err() != nil {
		return errors.New("cleanup inherited cancelled run context")
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 3*time.Minute {
		return errors.New("cleanup deadline invalid")
	}
	return f.failure
}
func TestExedevInterruptedRunUsesIndependentBoundedCleanup(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	f := &exedevInterruptedCleanup{parent: parent}
	if e := deleteExedev(f); e != nil || !f.called {
		t.Fatal("interrupted cleanup failed", e)
	}
	f.failure = errors.New("provider refused cleanup")
	if e := deleteExedev(f); !errors.Is(e, f.failure) {
		t.Fatal("cleanup refusal suppressed", e)
	}
}

func TestExedevCleanupApprovalBeforeCredentials(t *testing.T) {
	var out, err bytes.Buffer
	code := run([]string{"cleanup", "exe.dev", "-exedev-state", "/does/not/exist", "-o", "json"}, &out, &err)
	if code != exitApproval || !strings.Contains(out.String(), "needs_approval") {
		t.Fatalf("cleanup approval gate failed: %d", code)
	}
}
