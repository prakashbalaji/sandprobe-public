package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"sandprobe/internal/report"
)

func doc(letter string, valid, complete bool) report.Doc {
	return report.Doc{Schema: report.Schema, Run: report.Run{ID: "r1", Provider: "sprites", StartedAt: "2026-11-10T08:50:00Z"},
		Grade:   report.Grade{Letter: letter, Valid: valid, Complete: complete, Counts: map[string]int{}},
		Cleanup: report.Cleanup{Outcome: "NOT confirmed deleted: delete sprite sandprobe-x (sprite-1) in org o by hand"}}
}

// OUT-4: a box not confirmed deleted ends 7, over every other outcome, and both reports are still written.
func TestFinish(t *testing.T) {
	for name, tc := range map[string]struct {
		d       report.Doc
		cleaned bool
		min     string
		want    int
	}{
		"graded and clean":                    {doc("A", true, true), true, "", exitGraded},
		"incomplete":                          {doc("C", true, false), true, "", exitPartial},
		"invalid":                             {doc("", false, false), true, "", exitPartial},
		"below -min":                          {doc("D", true, true), true, "B", exitBelowMin},
		"below -min, and incomplete":          {doc("D", true, false), true, "B", exitBelowMin},
		"cleanup unconfirmed":                 {doc("A", true, true), false, "", exitCleanup},
		"cleanup unconfirmed, below -min too": {doc("F", true, false), false, "B", exitCleanup},
		"cleanup unconfirmed, and invalid":    {doc("", false, false), false, "", exitCleanup},
	} {
		dir := t.TempDir()
		var out bytes.Buffer
		code, err := finish(opts{out: "json", stdout: &out}, runFlags{outDir: dir, min: tc.min, theme: "modern"}, tc.d, tc.cleaned)
		if err != nil || code != tc.want {
			t.Errorf("%s: exit %d, %v; want %d", name, code, err, tc.want)
		}
		for _, ext := range []string{".json", ".html"} {
			if _, err := os.Stat(filepath.Join(dir, "sandprobe-sprites-r1"+ext)); err != nil {
				t.Errorf("%s: the %s report wasn't written: %v", name, ext, err)
			}
		}
		var back report.Doc
		if json.Unmarshal(out.Bytes(), &back) != nil || back.Run.ID != "r1" {
			t.Errorf("%s: -o json didn't print the document", name)
		}
	}
	if failExit(false) != exitCleanup || failExit(true) != exitPartial {
		t.Error("a failed run with an unconfirmed cleanup must end 7")
	}
}

// AGT-3: outside a terminal, run without -y prints only the plan, creates nothing, and ends 3. The check runs before
// any provider is touched only when Sandprobe has a login and a canary, so it's covered live; here, usage and explain.
func TestCommands(t *testing.T) {
	var out, errs bytes.Buffer
	if code := run([]string{"explain", "amp-8.sys", "-o", "json"}, &out, &errs); code != 0 || !strings.Contains(out.String(), `"id": "AMP-8.sys"`) {
		t.Fatalf("explain: %d %s %s", code, out.String(), errs.String())
	}
	out.Reset()
	if code := run([]string{"run", "nowhere", "-o", "json"}, &out, &errs); code != exitUsage || !strings.Contains(out.String(), `"error": "usage"`) {
		t.Fatalf("an unknown provider: %d %s", code, out.String())
	}
	out.Reset()
	if code := run([]string{"explain", "XYZ-9", "-o", "json"}, &out, &errs); code != exitUsage || !strings.Contains(out.String(), `"fix"`) {
		t.Fatalf("an unknown check: %d %s", code, out.String())
	}
}

// A kubeconfig whose context for the cluster points anywhere but the recorded endpoint is refused before any pod is
// made.
func TestBindContext(t *testing.T) {
	if _, err := exec.LookPath("kubectl"); err != nil {
		t.Skip("needs kubectl")
	}
	kc := filepath.Join(t.TempDir(), "kubeconfig")
	os.WriteFile(kc, []byte(`apiVersion: v1
kind: Config
clusters:
- name: ours
  cluster: {server: "https://ours.example"}
- name: theirs
  cluster: {server: "https://theirs.example"}
users:
- name: u
  user: {token: "not-a-real-token"}
contexts:
- name: sandprobe-x
  context: {cluster: ours, user: u}
- name: other
  context: {cluster: theirs, user: u}
current-context: other
`), 0o600)
	if err := bindContext(kc, "sandprobe-x", "https://ours.example"); err != nil {
		t.Fatalf("the recorded context at the recorded endpoint: %v", err)
	}
	for name, tc := range map[string][2]string{
		"the context points at another cluster": {"sandprobe-x", "https://elsewhere.example"},
		"no such context":                       {"sandprobe-missing", "https://ours.example"},
		"the current context, not the recorded": {"other", "https://ours.example"},
	} {
		if err := bindContext(kc, tc[0], tc[1]); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
