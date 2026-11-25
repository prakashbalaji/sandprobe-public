package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// PRV-18, AGT-3: the plan and an unapproved run read no token and make no SDK call, whatever the environment holds; an
// approved run with no workspace named, or a bad one, stops before anything is contacted.
func TestModalPlanAndApproval(t *testing.T) {
	isolateCanary(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("MODAL_CONFIG_PATH", filepath.Join(home, "absent.toml"))
	t.Setenv("MODAL_SERVER_URL", "https://127.0.0.1:1") // a call to Modal would fail, not reach it
	t.Setenv("SANDPROBE_MODAL_WORKSPACE", "ws-a")
	var out, errs bytes.Buffer
	var p planDoc
	if code := run([]string{"plan", "modal", "-o", "json"}, &out, &errs); code != 0 || json.Unmarshal(out.Bytes(), &p) != nil || p.Provider != "modal" {
		t.Fatalf("plan: exit %d, %s", code, errs.String())
	}
	text := strings.Join(p.Creates, " ") + " " + p.Residual + " " + strings.Join(p.BoxNamed, " ")
	for _, want := range []string{"workspace ws-a", "15-minute timeout", "no injected secrets", "both stay", "modal app stop sandprobe", "SEC-4, EGR-3, AMP-6 and AMP-7", "open egress"} {
		if !strings.Contains(text, want) {
			t.Errorf("the plan doesn't say %q", want)
		}
	}
	out.Reset()
	if code := run([]string{"run", "modal", "-o", "json"}, &out, &errs); code != exitApproval || !strings.Contains(out.String(), `"needs_approval": true`) {
		t.Fatalf("unapproved: exit %d, %s", code, errs.String())
	}
	for _, w := range []string{"", "Not A Workspace", "-x", strings.Repeat("a", 65)} {
		t.Setenv("SANDPROBE_MODAL_WORKSPACE", w)
		errs.Reset()
		if code := run([]string{"run", "modal", "-y"}, &out, &errs); code != exitLogin || !strings.Contains(errs.String(), "SANDPROBE_MODAL_WORKSPACE") || strings.Contains(errs.String(), "canary") {
			t.Errorf("workspace %q: exit %d, %s", w, code, errs.String())
		}
	}
	if left, _ := filepath.Glob(filepath.Join(home, ".config", "sandprobe", "modal-*")); len(left) != 0 {
		t.Errorf("a run that never started left %v", left)
	}
	for _, args := range [][]string{{"plan", "modal", "-variant", "block"}, {"run", "modal", "-variant", "default", "-y"},
		{"plan", "modal", "-variant", "isolated"}, {"run", "modal", "-variant", "isolated", "-y"}, {"run", "modal", "-variant", "isolated"}, {"run", "modal", "-min", "6", "-y"}} {
		if code := run(args, &out, &errs); code != exitUsage {
			t.Errorf("%v: exit %d", args, code)
		}
	}
}

// PRV-18: providers says modal is ready from the workspace's name alone.
func TestModalReadiness(t *testing.T) {
	isolateCanary(t)
	t.Setenv("HOME", t.TempDir())
	for w, want := range map[string]bool{"": false, "ws-a": true} {
		t.Setenv("SANDPROBE_MODAL_WORKSPACE", w)
		if _, err := modalWorkspace(); (err == nil) != want {
			t.Errorf("%q: %v", w, err)
		}
	}
}

type modalCleanupFake struct{ err error }

func (f *modalCleanupFake) Destroy(ctx context.Context) error {
	if d, ok := ctx.Deadline(); !ok || time.Until(d) > 3*time.Minute || ctx.Err() != nil {
		return errors.New("the cleanup has no budget of its own")
	}
	return f.err
}

func TestModalCleanupBudget(t *testing.T) {
	if err := deleteModal(&modalCleanupFake{}); err != nil {
		t.Fatal(err)
	}
	if deleteModal(&modalCleanupFake{err: errors.New("refused")}) == nil {
		t.Fatal("a failed delete was ignored")
	}
}
