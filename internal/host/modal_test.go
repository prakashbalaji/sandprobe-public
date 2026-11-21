package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
