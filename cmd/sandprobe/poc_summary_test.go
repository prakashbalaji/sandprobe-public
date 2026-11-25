//go:build poc

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"sandprobe/internal/host"
	"sandprobe/internal/obs"
	"sandprobe/internal/report"
)

func docWith(findings ...report.Finding) report.Doc {
	return report.Doc{Grade: report.Grade{Valid: true, Complete: true}, Findings: findings}
}

// POC-7, POC-8: every finding bucketed by the table and by setup; an unbucketed one refused; no letter grade; hostile
// strings rendered as text.
func TestSummary(t *testing.T) {
	docs := map[string]report.Doc{
		"default":      docWith(report.Finding{ID: "EGR-2"}, report.Finding{ID: "EGR-1"}, report.Finding{ID: "AMP-2"}),
		"domain-empty": docWith(report.Finding{ID: "EGR-1"}, report.Finding{ID: "AMP-2"}, report.Finding{ID: "CHN-1", Checks: []string{"SEC-1", "EGR-1"}}),
	}
	v, err := buildSummary(docs, map[string]*rawRecord{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][2]int{}
	for _, r := range v.Rows {
		got[r.Setup] = [2]int{r.A, r.C}
	}
	if got["default"] != [2]int{1, 0} || got["domain-empty"] != [2]int{0, 1} {
		t.Fatalf("bucket counts by setup: %v", got)
	}
	if len(v.Gaps) != 1 || v.Gaps[0].Bucket != "C" {
		t.Fatalf("the gaps that apply: %+v", v.Gaps)
	}
	page, err := summaryHTML(v)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(page), ">F<") || strings.Contains(string(page), "grade") {
		t.Error("the summary shows a grade")
	}
	if _, err := buildSummary(map[string]report.Doc{"block": docWith(report.Finding{ID: "EGR-2"})}, nil); err == nil {
		t.Error("a finding outside POC-7's table was bucketed by judgment")
	}
	if _, err := buildSummary(map[string]report.Doc{"default": docWith(report.Finding{ID: "AMP-1"})}, nil); err == nil {
		t.Error("AMP-1 isn't in the table, yet it was bucketed")
	}
	v.Lines[0].Saw = `<script>alert(1)</script>`
	page, _ = summaryHTML(v)
	if strings.Contains(string(page), "<script>") {
		t.Error("a hostile string rendered as markup")
	}
}

// POC-5: no gate clears on evidence that proves nothing; the image list fails closed.
func TestEvidenceAndImages(t *testing.T) {
	good := obs.CanaryEvidence{Live: true, ReceiptsRead: true}
	if why := host.ModalUnsound(good, true, ""); why != "" {
		t.Fatalf("sound evidence refused: %s", why)
	}
	for name, ev := range map[string]obs.CanaryEvidence{
		"not armed":  {ReceiptsRead: true},
		"not read":   {Live: true},
		"overloaded": {Live: true, ReceiptsRead: true, Overloaded: true},
	} {
		if host.ModalUnsound(ev, true, "") == "" {
			t.Errorf("%s: cleared the gate", name)
		}
	}
	if host.ModalUnsound(good, false, "bad doc") == "" {
		t.Error("an invalid document cleared the gate")
	}
	dir := t.TempDir()
	if _, err := readImages(dir, false); err == nil {
		t.Error("a missing image list read as nothing to clean")
	}
	os.WriteFile(filepath.Join(dir, "images.json"), []byte("{oops"), 0o600)
	if err := noteImage(dir, "ws-a", "im-1"); err == nil {
		t.Error("a malformed image list was overwritten")
	}
	os.Remove(filepath.Join(dir, "images.json"))
	if err := noteImage(dir, "ws-a", "im-1"); err != nil {
		t.Fatal(err)
	}
	if list, err := readImages(dir, false); err != nil || len(list.IDs) != 1 || list.Workspace != "ws-a" {
		t.Fatalf("the kept image list: %+v %v", list, err)
	}
	// POC-1: the list stays bound to the workspace that built its images.
	if err := noteImage(dir, "ws-b", "im-2"); err == nil {
		t.Error("another workspace's image joined the list")
	}
	os.WriteFile(filepath.Join(dir, "images.json"), []byte(`["im-old"]`), 0o600)
	if _, err := readImages(dir, false); err == nil {
		t.Error("a list with no workspace read as one to clean")
	}
}

// Only a record that passed every gate, with its setup's own evidence, may be rendered or summarised; an invalid
// report is refused; Markdown cells can't be broken out of.
func TestSummaryInputs(t *testing.T) {
	sv := &obs.Survey{}
	ok := &rawRecord{Setup: "default", GatesPassed: true, Survey: sv, Doc: []byte("{}")}
	if err := recordSound(ok, "default"); err != nil {
		t.Fatal(err)
	}
	for name, rec := range map[string]*rawRecord{
		"ended early":       {Setup: "default", Survey: sv, Doc: []byte("{}"), Notes: []string{"ended early: twin"}},
		"another setup":     {Setup: "block", GatesPassed: true, Survey: sv, Doc: []byte("{}")},
		"no probe evidence": {Setup: "default", GatesPassed: true},
	} {
		if recordSound(rec, "default") == nil {
			t.Errorf("%s: rendered", name)
		}
	}
	if recordSound(&rawRecord{Setup: "domain-one", GatesPassed: true, Survey: sv, Doc: []byte("{}")}, "domain-one") == nil {
		t.Error("domain-one without its twin was rendered")
	}
	if recordSound(&rawRecord{Setup: "sidecar", GatesPassed: true, Survey: sv, Doc: []byte("{}"), Relay: &host.RelayLog{Complete: true}}, "sidecar") == nil {
		t.Error("sidecar without look rows was rendered")
	}
	bad := docWith()
	bad.Grade.Valid = false
	if _, err := buildSummary(map[string]report.Doc{"default": bad}, map[string]*rawRecord{}); err == nil {
		t.Error("an invalid report was summarised")
	}
	v, _ := buildSummary(map[string]report.Doc{"default": docWith()}, map[string]*rawRecord{"default": {Kernel: "4.4.0 | x |\n[click](http://evil)"}})
	out := string(summaryMD(v))
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "| default") && strings.Count(strings.ReplaceAll(l, `\|`, ""), "|") != 10 {
			t.Errorf("the kernel string broke the table row: %s", l)
		}
	}
	if strings.Contains(out, "[click](") {
		t.Error("a link from the box survived in the Markdown")
	}
}

// A report is summarised only beside the raw record of its own run; spend is the bound from set size and lifetime.
func TestSummaryBinding(t *testing.T) {
	if got := spend(600, 0); !strings.Contains(got, "$0.003") || !strings.Contains(got, "11 sandbox-minutes") || strings.Contains(got, "floor") {
		t.Errorf("10 minutes at Modal's default request: %s", got)
	}
	if got := spend(900, 1); strings.Contains(got, "floor") || !strings.Contains(got, "not confirmed deleted") {
		t.Errorf("an unconfirmed cleanup called the estimate a floor: %s", got)
	}
	at := time.Date(2026, 11, 10, 22, 0, 0, 0, time.UTC)
	rec := &rawRecord{Started: at.Add(-time.Minute), Ended: at.Add(160 * time.Second), Cleaned: true, // a slow last call
		Calls: []obs.ProviderCall{{At: at, Call: "modal create sandbox (default)"}, {At: at.Add(100 * time.Second), Call: "modal terminate"}}}
	if s := sandboxSeconds(rec); s != 160 {
		t.Errorf("lifetime to the end of teardown: %v", s)
	}
	rec.Cleaned = false
	if s := sandboxSeconds(rec); s != 900 {
		t.Errorf("a sandbox not confirmed deleted runs to its timeout: %v", s)
	}
}

// POC-7: SEC-2 and SEC-5 are B only when every named process is the sandbox's own.
func TestSummaryProcesses(t *testing.T) {
	withEv := func(ev string) map[string]report.Doc {
		dd := docWith(report.Finding{ID: "SEC-2"}, report.Finding{ID: "SEC-3"})
		dd.Checks = []report.Check{{ID: "SEC-2", Evidence: ev}}
		return map[string]report.Doc{"default": dd}
	}
	d := withEv("the agent can open /proc/1/environ, /proc/2/environ (nothing was read)")
	own := map[string]*rawRecord{"default": {Processes: map[string]string{"1": "dumb-init", "2": "sleep", "30": "sh"}}}
	if _, err := buildSummary(d, own); err != nil {
		t.Fatal(err)
	}
	if _, err := buildSummary(withEv("the agent can open /proc/77/environ (nothing was read)"), // exited before the names were listed
		map[string]*rawRecord{"default": {Processes: map[string]string{"1": "dumb-init"}}}); err == nil {
		t.Error("a found PID with no recorded name was bucketed")
	}
	other := map[string]*rawRecord{"default": {Processes: map[string]string{"1": "dumb-init", "2": "modal-agent"}}}
	if _, err := buildSummary(d, other); err == nil {
		t.Error("a process that isn't the sandbox's own was bucketed")
	}
	if _, err := buildSummary(d, map[string]*rawRecord{"default": {Processes: map[string]string{"1": "sleep", "2": "sleep"}}}); err == nil {
		t.Error("PID 1 that isn't Modal's init was bucketed")
	}
	// The VM: other processes' environment or memory there has no row, so it stops the summary for a reviewed change;
	// the guest's own kernel is by design.
	vm := withEv("the agent can open /proc/1/environ, /proc/981/environ (nothing was read)")["default"]
	vm.Findings = append(vm.Findings, report.Finding{ID: "AMP-8.blk"})
	vm.Checks = append(vm.Checks, report.Check{ID: "AMP-8.blk", Evidence: "the agent can read /dev/loop0, /dev/vda, /dev/vda1, /dev/nullb0, /dev/zram0, /dev/ram0 (never opened)"})
	vrec := &rawRecord{Processes: map[string]string{"1": "provider-agent", "981": "sleep", "2": "kthreadd"}}
	if _, err := buildSummary(map[string]report.Doc{"block-vm": vm}, map[string]*rawRecord{"block-vm": vrec}); err == nil ||
		!strings.Contains(err.Error(), "isn't in POC-7's table") {
		t.Fatalf("another process's environment in the VM was bucketed: %v", err)
	}
	vm.Findings = slices.DeleteFunc(slices.Clone(vm.Findings), func(f report.Finding) bool { return f.ID == "SEC-2" || f.ID == "SEC-5" })
	v, err := buildSummary(map[string]report.Doc{"block-vm": vm}, map[string]*rawRecord{"block-vm": vrec})
	if err != nil {
		t.Fatal(err)
	}
	if r := v.Rows[0]; r.D != 0 || r.Design != 1 || r.B != 1 { // AMP-8.blk by design, SEC-3 B
		t.Errorf("block-vm's row: %+v", r)
	}
	for _, g := range v.Gaps {
		if g.Bucket == "by design" || g.Bucket == "D" {
			t.Errorf("a %s line counted as a gap", g.Bucket)
		}
	}
	// The by-design row holds only for the guest surfaces it names; a new device is refused.
	odd := vm
	odd.Checks = append([]report.Check{}, vm.Checks...)
	odd.Checks[len(odd.Checks)-1].Evidence = "the agent can read /dev/vda, /dev/nvme0n1 (never opened)"
	if _, err := buildSummary(map[string]report.Doc{"block-vm": odd}, map[string]*rawRecord{"block-vm": vrec}); err == nil {
		t.Error("a device the row doesn't name was placed as by design")
	}
	// POC-7's rows are disjoint: AMP-8 is by design only in the VM, D only on gVisor.
	for _, s := range []string{"default", "domain-empty", "domain-one", "block", "sidecar", "block-vm"} {
		for _, id := range []string{"AMP-8.sys", "AMP-8.blk", "SEC-2", "SEC-5"} {
			var hits []string
			for _, b := range bucketTable {
				if b.matches(id, s) {
					hits = append(hits, b.Bucket)
				}
			}
			want := 1
			if s == "block-vm" && (id == "SEC-2" || id == "SEC-5") {
				want = 0 // no row: it stops the summary for a reviewed change
			}
			if len(hits) != want {
				t.Errorf("%s in %s matches %v rows", id, s, hits)
			}
		}
	}
	// What got out lists the ports that reached the canary, and only those.
	one := &rawRecord{Setup: "default", Manifest: obs.Manifest{CheckNonces: map[string]string{"EGR-5.80": "c80", "EGR-5.22": "c22", "EGR-1": "cd"}},
		Evidence: obs.CanaryEvidence{Receipts: []obs.Receipt{{Nonce: "c80", Proto: "tcp", Port: 80}, {Nonce: "cd", Proto: "dns", Port: 53}}}}
	if got := gotOut(one); got != "DNS, TCP 80" {
		t.Errorf("what got out: %q", got)
	}
	if got := gotOut(&rawRecord{}); got != "nothing" {
		t.Errorf("no receipt: %q", got)
	}
	if _, err := buildSummary(d, map[string]*rawRecord{"default": {}}); err == nil {
		t.Error("SEC-2 bucketed with no process names")
	}
}

// POC-1: without SANDPROBE_MODAL_WORKSPACE the PoC stops before the canary, Docker or Modal is asked anything; cleanup
// deletes only in the workspace its list names.
func TestPocWorkspaceFirst(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SANDPROBE_MODAL_WORKSPACE", "")
	var out, errs bytes.Buffer
	if code := run([]string{"poc", "modal", "run", "-variant", "default", "-out", t.TempDir(), "-y"}, &out, &errs); code != exitLogin ||
		!strings.Contains(errs.String(), "SANDPROBE_MODAL_WORKSPACE") {
		t.Errorf("run without a workspace: exit %d, %s", code, errs.String())
	}
	dir := t.TempDir()
	if err := noteImage(dir, "ws-a", "im-1"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SANDPROBE_MODAL_WORKSPACE", "ws-b")
	errs.Reset() // a run into another workspace's list stops before any image is built, or the canary is asked
	if code := run([]string{"poc", "modal", "run", "-variant", "default", "-out", dir, "-y"}, &out, &errs); code != exitUsage || !strings.Contains(errs.String(), "for workspace ws-a") {
		t.Errorf("run into another workspace's list: exit %d, %s", code, errs.String())
	}
	errs.Reset()
	if code := run([]string{"poc", "modal", "cleanup", "-out", dir, "-y"}, &out, &errs); code != exitCleanup || !strings.Contains(errs.String(), "ws-a") {
		t.Errorf("cleanup in another workspace: exit %d, %s", code, errs.String())
	}
}
