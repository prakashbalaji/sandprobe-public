package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sandprobe/internal/grade"
	"sandprobe/internal/host"
)

func TestBasetenPlanAndApproval(t *testing.T) {
	var out, errs bytes.Buffer
	p := basetenPlan(&host.SSMCanary{Addr: "203.0.113.1", Dom: "probe.example"}, runFlags{basetenTeam: "team-test", basetenRegion: "us-pdx-1"})
	for _, s := range []string{"15-minute", "no secrets", "no volumes"} {
		// Different sentences describe the no-volume reset and no-secret creation.
		text := strings.Join(p.Creates, " ") + " " + p.Residual
		if s == "no volumes" {
			s = "no secrets, previews or volumes"
		}
		if !strings.Contains(strings.ToLower(text), strings.ToLower(s)) {
			t.Error("missing plan boundary", s)
		}
	}
	ok, err := approveBaseten(opts{out: "json", stdout: &out}, p, &errs)
	if ok || err != nil || !strings.Contains(out.String(), `"needs_approval": true`) {
		t.Fatal("noninteractive run did not stop at plan")
	}
	out.Reset()
	ok, err = approveBaseten(opts{yes: true, out: "json", stdout: &out}, p, &errs)
	if !ok || err != nil || out.Len() != 0 {
		t.Fatal("approved plan still gated")
	}
	for _, id := range []string{"SEC-4", "EGR-3", "AMP-6", "AMP-7"} {
		if host.BasetenExclusions()[id] == "" {
			t.Error("missing provider exclusion", id)
		}
	}
}
func TestBasetenCleanupOutranksReportFailure(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "not-a-directory")
	os.WriteFile(file, []byte("occupied"), 0600)
	var out, errs bytes.Buffer
	d := doc("F", true, true)
	_, err := finishBaseten(opts{out: "json", stdout: &out}, runFlags{outDir: filepath.Join(file, "reports"), theme: "modern"}, d, false, nil)
	if err == nil || reportErr(opts{out: "json", stdout: &out}, &errs, err) != exitCleanup {
		t.Fatal("report failure masked cleanup exit 7")
	}
}
func TestBasetenMissingKeyIsActionable(t *testing.T) {
	t.Setenv("BASETEN_API_KEY", "")
	_, err := basetenClient(runFlags{basetenKeyFile: filepath.Join(t.TempDir(), "missing")})
	ce, ok := err.(*cliError)
	if !ok || ce.exit != exitLogin || !strings.Contains(ce.Fix, "SANDPROBE_BASETEN_KEY_FILE") {
		t.Fatal("missing key did not explain safe setup")
	}
}

type fakeBasetenLifecycle struct {
	retains, deletes        int
	retentionErr, deleteErr error
	cleanupCancelled        bool
	duringRetain            func()
}

func (f *fakeBasetenLifecycle) ID() string        { return "sandprobe-test" }
func (f *fakeBasetenLifecycle) StatePath() string { return "/tmp/private journal's/state" }
func (f *fakeBasetenLifecycle) Retain(ctx context.Context) (time.Time, error) {
	f.retains++
	if f.duringRetain != nil {
		f.duringRetain()
	}
	return time.Now().Add(time.Hour), f.retentionErr
}
func (f *fakeBasetenLifecycle) Destroy(ctx context.Context) error {
	f.deletes++
	f.cleanupCancelled = ctx.Err() != nil
	return f.deleteErr
}
func TestBasetenLifecycleRetentionPolicy(t *testing.T) {
	for _, mode := range []string{"ordinary", "keep", "invalid", "incomplete", "execution-error", "interrupted", "retention-error", "cancel-during-retain", "cleanup-error"} {
		t.Run(mode, func(t *testing.T) {
			f := &fakeBasetenLifecycle{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			run := &host.Run{Report: grade.Report{Valid: true, Complete: true, Letter: "F"}}
			var executionErr error
			switch mode {
			case "invalid":
				run.Report.Valid = false
			case "incomplete":
				run.Report.Complete = false
			case "execution-error":
				executionErr = errors.New("failed")
			case "interrupted":
				cancel()
			case "cancel-during-retain":
				f.duringRetain = cancel
			case "retention-error":
				f.retentionErr = errors.New("expiry unverified")
			case "cleanup-error":
				executionErr = errors.New("failed")
				f.deleteErr = errors.New("delete refused")
			}
			outcome, retained, satisfied, err := completeBasetenLifecycle(ctx, f, run, executionErr, mode != "ordinary")
			if mode == "keep" {
				if retained == nil || !satisfied || err != nil || f.retains != 1 || f.deletes != 0 || !strings.Contains(outcome, "INTENTIONALLY RETAINED") {
					t.Fatal("retention not explicit or sandbox deleted")
				}
				if !strings.Contains(outcome, `-baseten-state '/tmp/private journal'\''s/state' -y`) {
					t.Fatal("unsafe cleanup command quoting", outcome)
				}
				d := doc("F", true, true)
				d.Cleanup.Outcome = outcome
				d.Cleanup.Retention = retained
				var out bytes.Buffer
				code, e := finishBaseten(opts{out: "json", stdout: &out}, runFlags{outDir: t.TempDir(), theme: "modern", min: "C"}, d, true, nil)
				if e != nil || code != exitBelowMin || !strings.Contains(out.String(), `"retention"`) || !strings.Contains(out.String(), `"cleanup_command"`) {
					t.Fatal("retention masked grade gate or missing output", e, code)
				}
			} else if retained != nil || f.deletes != 1 || f.cleanupCancelled {
				t.Fatal("failed/non-retention run did not use independent cleanup")
			}
			if mode == "cleanup-error" && (satisfied || err == nil) {
				t.Fatal("cleanup failure masked")
			}
		})
	}
}
func TestBasetenCleanupApprovalBeforeCredentials(t *testing.T) {
	t.Setenv("BASETEN_API_KEY", "")
	var out, errs bytes.Buffer
	code, err := cleanupBaseten(opts{out: "json", stdout: &out}, runFlags{basetenState: "/no/private/journal"}, []string{"baseten"}, &errs)
	if code != exitApproval || err != nil || !strings.Contains(out.String(), `"needs_approval": true`) {
		t.Fatal("cleanup touched credentials/provider before approval")
	}
	for _, args := range [][]string{{"run", "sprites", "-keep-sandbox"}, {"plan", "aws-nitro", "-keep-sandbox"}, {"providers", "-keep-sandbox"}, {"run", "baseten", "-baseten-state", "/tmp/x"}} {
		out.Reset()
		if code := run(args, &out, &errs); code != exitUsage {
			t.Fatal("Baseten-only flag ignored", args, code)
		}
	}
}

func TestBasetenLifecycleFailureStillWritesReport(t *testing.T) {
	for _, tc := range []struct {
		cleaned bool
		min     string
		want    int
	}{{true, "", exitPartial}, {true, "C", exitBelowMin}, {false, "", exitCleanup}} {
		var out bytes.Buffer
		d := doc("F", true, true)
		d.Cleanup.Outcome = "retention unavailable; cleanup recorded"
		code, err := finishBaseten(opts{out: "json", stdout: &out}, runFlags{outDir: t.TempDir(), theme: "modern", min: tc.min}, d, tc.cleaned, errors.New("expiry could not be verified"))
		if err != nil || code != tc.want || !strings.Contains(out.String(), "Lifecycle handling: expiry could not be verified") {
			t.Fatal("lifecycle failure lost report or exit priority", code, err)
		}
	}
}
