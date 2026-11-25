package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	modal "github.com/modal-labs/modal-client/go"

	"sandprobe/internal/grade"
	"sandprobe/internal/obs"
)

// PRV-5, GRD-3: Modal's exclusions are skipped with their own reasons, the manifest names no metadata address, vsock
// port, Kubernetes API or proxy, and the grader accepts the manifest.
func TestModalExclusions(t *testing.T) {
	s := &obs.Survey{Schema: obs.SurveySchema, KubeAPI: "10.96.0.1:443", Vsock: false,
		Proxy: &obs.ProxySetting{Var: "HTTPS_PROXY", Scheme: "http", Addr: "proxy.modal.internal:3128"}}
	m, in := Plan(Options{Mode: "exec", Excluded: ModalExcluded}, s, "sb-1", Storage{}, "203.0.113.10", "sandprobe.test", "pin")
	for id, why := range ModalExcluded {
		if slices.Contains(m.Selected, id) || m.Skipped[id] != why {
			t.Errorf("%s: want skipped for its PRV-5 reason, got selected=%v reason=%q", id, slices.Contains(m.Selected, id), m.Skipped[id])
		}
	}
	if m.KubeAPI != "" || in.KubeAPI != "" || m.Proxy != "" || in.Proxy != "" || m.ProxyMalformed {
		t.Fatalf("an excluded API or proxy is still named: %q %q %q", m.KubeAPI, m.Proxy, in.Proxy)
	}
	for id, ep := range m.Endpoints {
		if strings.HasPrefix(ep, "169.254.") || strings.Contains(ep, "modal") {
			t.Errorf("%s plans %s", id, ep)
		}
	}
	if err := grade.ManifestSound(m); err != nil {
		t.Fatalf("the grader refuses the manifest: %v", err)
	}
	if _, err := Execute(context.Background(), surveyBox{}, nil, Options{Excluded: map[string]string{"AMP-2": "no"}}); err == nil {
		t.Fatal("a check GRD-3 never lets be skipped was excluded")
	}
}

// POC-2: each setup's create request is its table row; an empty allowlist stays allowlist mode, never open.
func TestModalSetups(t *testing.T) {
	tags := map[string]string{"sandprobe-run": "x"}
	for _, setup := range ModalSetups {
		spec, err := ModalSetup(setup, "ctwin", "probe.example")
		if err != nil {
			t.Fatal(err)
		}
		p := modalParams(spec, tags, nil)
		if p.Timeout != modalTimeout || p.Tags["sandprobe-run"] != "x" || p.CPU != 0 || p.CPULimit != 0 || p.MemoryMiB != 0 || p.MemoryLimitMiB != 0 {
			t.Errorf("%s: no backstop timeout or run tag, or a size other than Modal's default", setup)
		}
		dom, cidr := p.OutboundDomainAllowlist, p.OutboundCIDRAllowlist
		proxy, _ := p.ExperimentalOptions["proxy_traffic_via_sidecar"].(string)
		ok := false
		switch setup {
		case "default":
			ok = !p.BlockNetwork && dom == nil && cidr == nil && p.Runtime == "" && proxy == ""
		case "domain-empty":
			ok = !p.BlockNetwork && dom != nil && dom.Entries != nil && len(dom.Entries) == 0 && cidr == nil
		case "domain-one":
			ok = !p.BlockNetwork && dom != nil && slices.Equal(dom.Entries, []string{"ctwin.canary.probe.example"}) && cidr == nil
		case "block":
			ok = p.BlockNetwork && dom == nil && cidr == nil && p.Runtime == ""
		case "block-vm":
			ok = p.BlockNetwork && dom == nil && cidr == nil && p.Runtime == modal.SandboxRuntimeVM
		case "sidecar":
			ok = !p.BlockNetwork && dom == nil && cidr != nil && len(cidr.Entries) == 0 && proxy == "watch"
		}
		if !ok {
			t.Errorf("%s: the create request doesn't match its row: %+v", setup, p)
		}
	}
	if _, err := ModalSetup("domain-one", "", ""); err == nil {
		t.Error("domain-one without its twin was accepted")
	}
	if _, err := ModalSetup("open-sesame", "", ""); err == nil {
		t.Error("an unknown setup was accepted")
	}
}

type fakeModal struct {
	createErr   error
	created     []ModalSpec
	terminated  []string
	running     []string
	termErr     error
	finished    bool
	execErr     error
	probeOutput string
}

func (f *fakeModal) Create(_ context.Context, spec ModalSpec, _ map[string]string) (string, error) {
	f.created = append(f.created, spec)
	if f.createErr != nil {
		return "", f.createErr
	}
	return "sb-1", nil
}

func (f *fakeModal) Exec(_ context.Context, id string, args []string, stdin []byte) ([]byte, []byte, int, error) {
	if f.execErr != nil {
		return nil, nil, -1, f.execErr
	}
	if args[0] == "sh" {
		sum := sha256sum(stdin)
		return []byte(sum + "  probe\n"), nil, 0, nil
	}
	return []byte(f.probeOutput), nil, 0, nil
}

func (f *fakeModal) Terminate(_ context.Context, id string) error {
	f.terminated = append(f.terminated, id)
	if f.termErr == nil {
		f.finished = true
	}
	return f.termErr
}

func (f *fakeModal) Finished(context.Context, string) (bool, error) { return f.finished, nil }

func (f *fakeModal) Running(context.Context, map[string]string) ([]string, error) {
	return f.running, nil
}

// POC-9, PRV-1: the box is terminated by its own ID and confirmed by poll and by tag; a failed terminate, or a
// sandbox of the run's tag still running, is reported.
func TestModalBox(t *testing.T) {
	ctx := context.Background()
	f := &fakeModal{probeOutput: `{"ok":true}`}
	spec, _ := ModalSetup("default", "", "")
	b, err := CreateModal(ctx, f, spec)
	if err != nil || b.ID() != "sb-1" || b.Tags["sandprobe-run"] == "" {
		t.Fatalf("create: %v %+v", err, b)
	}
	if err := b.Upload(ctx, []byte("probe-bytes")); err != nil {
		t.Fatal(err)
	}
	if out, err := b.Probe(ctx, []string{"-survey"}, nil); err != nil || string(out) != `{"ok":true}` {
		t.Fatalf("probe: %q %v", out, err)
	}
	if _, err := b.Probe(ctx, []string{"; rm -rf /"}, nil); err == nil {
		t.Fatal("a non-probe argument was passed")
	}
	if err := b.Destroy(ctx); err != nil || !slices.Equal(f.terminated, []string{"sb-1"}) {
		t.Fatalf("destroy: %v %v", err, f.terminated)
	}
	f2 := &fakeModal{termErr: &ModalError{Op: "terminate", Category: "failed", Code: "Unavailable"}}
	b2, _ := CreateModal(ctx, f2, spec)
	if err := b2.Destroy(ctx); err == nil {
		t.Fatal("a failed terminate counted as deleted")
	}
	f4 := &fakeModal{createErr: &ModalError{Op: "create", Category: "timed out or canceled", Code: "DeadlineExceeded"}}
	b4, err := CreateModal(ctx, f4, spec)
	if err == nil || b4.ID() != "" {
		t.Fatal("a failed create returned an ID")
	}
	if err := b4.Destroy(ctx); err == nil || !strings.Contains(err.Error(), b4.Tags["sandprobe-run"]) {
		t.Fatalf("a create with no ID counted as cleaned up on an empty listing: %v", err) // it may show up later
	}
	f3 := &fakeModal{running: []string{"sb-9"}}
	b3, _ := CreateModal(ctx, f3, spec)
	if err := b3.Destroy(ctx); err == nil || !strings.Contains(err.Error(), "sb-9") {
		t.Fatalf("a sandbox of the run's tag still running wasn't reported: %v", err)
	}
}

// POC-1: an SDK error's text never reaches an error, a call record or anything built from them.
func TestModalTokenNeverLeaks(t *testing.T) {
	const sentinel = "as-SENTINEL0123456789abcdef"
	sdkErr := errors.New("rpc error: code = Unauthenticated desc = bad token " + sentinel)
	ctx := context.Background()
	f := &fakeModal{execErr: sanitize("exec", sdkErr)}
	spec, _ := ModalSetup("default", "", "")
	b, _ := CreateModal(ctx, f, spec)
	err := b.Upload(ctx, []byte("x"))
	calls, _ := json.Marshal(b.Calls)
	if err == nil || strings.Contains(err.Error(), sentinel) || strings.Contains(string(calls), sentinel) {
		t.Fatalf("the SDK's text leaked: %v %s", err, calls)
	}
	if got := sanitize("create", sdkErr).Error(); strings.Contains(got, sentinel) || !strings.HasPrefix(got, "modal create: ") {
		t.Fatalf("sanitize: %q", got)
	}
}

func sha256sum(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// journalModal checks what is on disk at each step of a recorded run (PRV-18).
type journalModal struct {
	fakeModal
	t           *testing.T
	dir         string
	lockOnMake  bool // the journal's directory stops being writable during the create
	sawAtCreate modalJournal
}

func (f *journalModal) Create(ctx context.Context, spec ModalSpec, tags map[string]string) (string, error) {
	f.sawAtCreate = readModalJournal(f.t, f.dir)
	if f.sawAtCreate.Tag != tags["sandprobe-run"] {
		f.t.Errorf("the create's tag %q isn't the journal's %q", tags["sandprobe-run"], f.sawAtCreate.Tag)
	}
	if f.lockOnMake {
		os.Chmod(f.dir, 0o500)
	}
	return f.fakeModal.Create(ctx, spec, tags)
}

func readModalJournal(t *testing.T, dir string) (j modalJournal) {
	t.Helper()
	found, _ := filepath.Glob(filepath.Join(dir, "modal-*.state"))
	if len(found) != 1 {
		t.Fatalf("journals: %v", found)
	}
	if st, err := os.Stat(found[0]); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("the journal isn't private: %v %v", st, err)
	}
	b, _ := os.ReadFile(found[0])
	if err := json.Unmarshal(b, &j); err != nil {
		t.Fatal(err)
	}
	return j
}

// PRV-18, AGENTS rule 8: the tag is on disk before the create and the ID after it; nothing is created without the
// journal, nothing runs in a sandbox whose ID isn't in it, and only a confirmed deletion removes it.
func TestModalJournal(t *testing.T) {
	ctx := context.Background()
	spec, _ := ModalSetup("default", "", "")
	make1 := func(t *testing.T, f *journalModal) (*ModalBox, error) {
		f.t, f.dir = t, t.TempDir()
		t.Cleanup(func() { os.Chmod(f.dir, 0o700) })
		return CreateModalRecorded(ctx, f, spec, f.dir, "ws-a", "im-1")
	}
	t.Run("recorded, then removed", func(t *testing.T) {
		f := &journalModal{}
		b, err := make1(t, f)
		if err != nil {
			t.Fatal(err)
		}
		if s := f.sawAtCreate; s.ID != "" || s.Workspace != "ws-a" || s.ImageID != "im-1" || s.App != ModalApp {
			t.Errorf("before the create: %+v", s)
		}
		if j := readModalJournal(t, f.dir); j.ID != "sb-1" {
			t.Errorf("after the create: %+v", j)
		}
		if err := b.Destroy(ctx); err != nil || !slices.Equal(f.terminated, []string{"sb-1"}) {
			t.Fatalf("destroy: %v %v", err, f.terminated)
		}
		if left, _ := os.ReadDir(f.dir); len(left) != 0 {
			t.Errorf("a confirmed deletion left %v", left)
		}
	})
	t.Run("no journal, no create", func(t *testing.T) {
		f := &journalModal{}
		dir := filepath.Join(t.TempDir(), "locked")
		os.Mkdir(dir, 0o500)
		b, err := CreateModalRecorded(ctx, f, spec, dir, "ws-a", "im-1")
		if b != nil || err == nil || len(f.created) != 0 {
			t.Fatalf("created without a journal: %v %v", b, err)
		}
	})
	t.Run("the ID can't be recorded", func(t *testing.T) {
		f := &journalModal{lockOnMake: true}
		b, err := make1(t, f)
		if err == nil || b == nil || b.SandboxID != "sb-1" || !strings.Contains(err.Error(), "nothing runs") {
			t.Fatalf("%v %+v", err, b)
		}
		os.Chmod(f.dir, 0o700)
		if err := b.Destroy(ctx); err != nil || !slices.Equal(f.terminated, []string{"sb-1"}) {
			t.Fatalf("destroy: %v %v", err, f.terminated)
		}
	})
	for name, f := range map[string]*journalModal{
		"a create with no ID":  {fakeModal: fakeModal{createErr: &ModalError{Op: "create", Category: "timed out or canceled", Code: "DeadlineExceeded"}}},
		"a failed terminate":   {fakeModal: fakeModal{termErr: &ModalError{Op: "terminate", Category: "failed", Code: "Unavailable"}}},
		"still running by tag": {fakeModal: fakeModal{running: []string{"sb-9"}}},
	} {
		t.Run(name+" keeps the journal", func(t *testing.T) {
			b, _ := make1(t, f)
			if err := b.Destroy(ctx); err == nil {
				t.Fatal("counted as deleted")
			}
			if j := readModalJournal(t, f.dir); j.Tag != b.Tags["sandprobe-run"] {
				t.Errorf("the journal doesn't hold the run's tag: %+v", j)
			}
			if slices.Contains(f.terminated, "sb-9") || f.createErr != nil && len(f.terminated) != 0 {
				t.Errorf("terminated something by tag: %v", f.terminated)
			}
		})
	}
}

// PRV-18: the workspace name a run may use.
func TestModalWorkspaceName(t *testing.T) {
	for name, ok := range map[string]bool{"rc-1": true, "a": true, "": false, "-a": false, "A": false, "a b": false, "a/b": false, strings.Repeat("a", 65): false} {
		if (ModalWorkspace(name) == nil) != ok {
			t.Errorf("%q", name)
		}
	}
}
