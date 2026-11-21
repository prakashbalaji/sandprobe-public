package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestBoatPlanAndApprovalPrecedeCredentials(t *testing.T) {
	for _, cmd := range []string{"plan", "run"} {
		var out, err bytes.Buffer
		code := run([]string{cmd, "boat", "-o", "json"}, &out, &err)
		want := 0
		if cmd == "run" {
			want = exitApproval
		}
		if code != want || !strings.Contains(out.String(), "noEnv=true") {
			t.Fatalf("plan/approval failed code=%d", code)
		}
	}
}

type boatInterruptedCleanup struct {
	parent  context.Context
	called  bool
	failure error
}

func (f *boatInterruptedCleanup) Destroy(ctx context.Context) error {
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
func TestBoatInterruptedRunUsesIndependentBoundedCleanup(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	f := &boatInterruptedCleanup{parent: parent}
	if e := deleteBoat(f); e != nil || !f.called {
		t.Fatal("interrupted cleanup failed", e)
	}
	f.failure = errors.New("provider refused cleanup")
	if e := deleteBoat(f); !errors.Is(e, f.failure) {
		t.Fatal("cleanup refusal suppressed", e)
	}
}
