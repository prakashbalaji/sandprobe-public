package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
)

// fakeKube plays kubectl: "get pod" answers from uids in turn ("" means NotFound), and every call is recorded.
type fakeKube struct {
	calls  [][]string
	uids   []string
	upload string
	stdin  []byte
}

func (f *fakeKube) cli(_ context.Context, stdin io.Reader, stdout, stderr io.Writer, args ...string) error {
	if args[2] != "--context" || args[3] != "ctx-1" {
		return errors.New("a call without the recorded context")
	}
	args = args[4:] // --kubeconfig <path> --context <name>
	f.calls = append(f.calls, args)
	if b, _ := io.ReadAll(stdin); len(b) > 0 {
		f.stdin = b
	}
	switch {
	case args[0] == "create":
		io.WriteString(stdout, "uid-1")
	case args[0] == "get" && args[1] == "pod" && strings.Contains(strings.Join(args, " "), "nodeName"):
		io.WriteString(stdout, "node-1")
	case args[0] == "get" && args[1] == "node":
		io.WriteString(stdout, "amd64")
	case args[0] == "get" && args[1] == "pod":
		if len(f.uids) == 0 {
			return errors.New("no lookup scripted")
		}
		u := f.uids[0]
		f.uids = f.uids[1:]
		if u == "" {
			fmt.Fprintf(stderr, "Error from server (NotFound): pods %q not found; token=secret-token-xyz", args[2])
			return errors.New("exit status 1")
		}
		io.WriteString(stdout, u)
	case args[0] == "exec" && slices.Contains(args, "sh"):
		fmt.Fprintf(stdout, "%s  /tmp/x/probe\n", f.upload)
	}
	return nil
}

func TestCreatePod(t *testing.T) {
	f := &fakeKube{}
	orig := podCLI
	defer func() { podCLI = orig }()
	podCLI = f.cli
	f.uids = []string{"uid-1"} // the readiness exec checks the UID first
	p, err := CreatePod(context.Background(), "/k", "ctx-1", PodSpec{Image: "img", RuntimeClass: "isolated-sandbox", NetworkIsolated: true})
	if err != nil || p.UID != "uid-1" || p.Arch != "amd64" || !strings.HasPrefix(p.Name, "sandprobe-") {
		t.Fatalf("pod %+v, %v", p, err)
	}
	var m struct {
		Metadata struct{ Annotations map[string]string }
		Spec     struct{ RuntimeClassName string }
	}
	json.Unmarshal(f.stdin, &m)
	if m.Spec.RuntimeClassName != "isolated-sandbox" || m.Metadata.Annotations["sandbox.amazonaws.com/network-isolated"] != "true" {
		t.Fatalf("manifest: %s", f.stdin)
	}
	if p.Calls[0].ID != "uid-1" {
		t.Error("PRV-3: the create's call must record the UID it returned")
	}
}

func TestPodUploadProbeDestroy(t *testing.T) {
	probe := []byte("the probe")
	sum := sha256.Sum256(probe)
	f := &fakeKube{upload: hex.EncodeToString(sum[:]), uids: []string{"uid-1", "uid-1"}}
	p := &PodBox{Kubeconfig: "/k", Context: "ctx-1", Name: "sandprobe-abc", UID: "uid-1", kubectl: f.cli}
	if err := p.Upload(context.Background(), probe); err != nil || string(f.stdin) != "the probe" {
		t.Fatalf("upload: %v", err)
	}
	if _, err := p.Probe(context.Background(), []string{"-survey"}, nil); err != nil {
		t.Fatal(err)
	}
	if c := f.calls[len(f.calls)-1]; !slices.Equal(c, []string{"exec", "-i", "sandprobe-abc", "-c", "agent", "--", "env", "SANDPROBE_TWIN=1", p.ProbePath, "-survey"}) {
		t.Fatalf("probe ran as %v", c)
	}
	if _, err := p.Probe(context.Background(), []string{"-survey; reboot"}, nil); err == nil {
		t.Fatal("want a non-flag argument refused")
	}
	// another pod by that name: nothing is uploaded, run or deleted there
	f = &fakeKube{upload: hex.EncodeToString(sum[:]), uids: []string{"uid-9", "uid-9", "uid-9"}}
	p = &PodBox{Kubeconfig: "/k", Context: "ctx-1", Name: "sandprobe-abc", UID: "uid-1", ProbePath: "/tmp/x/probe", kubectl: f.cli}
	_, perr := p.Probe(context.Background(), []string{"-survey"}, nil)
	if p.Upload(context.Background(), probe) == nil || perr == nil || p.Destroy(context.Background()) == nil {
		t.Fatal("want upload, probe and delete refused on another pod by that name")
	}
	if slices.ContainsFunc(f.calls, func(c []string) bool { return c[0] == "exec" || c[0] == "delete" }) {
		t.Fatal("nothing may be run on, or deleted from, another pod")
	}
	for name, tc := range map[string]struct {
		uids        []string
		ok, deleted bool
	}{
		"deleted, then NotFound": {[]string{"uid-1", ""}, true, true},
		"already gone":           {[]string{""}, true, false},
		"still there after":      {[]string{"uid-1", "uid-1"}, false, true},
	} {
		f := &fakeKube{uids: tc.uids}
		p := &PodBox{Kubeconfig: "/k", Context: "ctx-1", Name: "sandprobe-abc", UID: "uid-1", kubectl: f.cli}
		err := p.Destroy(context.Background())
		deleted := slices.ContainsFunc(f.calls, func(c []string) bool { return c[0] == "delete" })
		if (err == nil) != tc.ok || deleted != tc.deleted {
			t.Errorf("%s: err %v, delete called %v", name, err, deleted)
		}
		b, _ := json.Marshal(p.Calls)
		if strings.Contains(string(b), "secret-token") {
			t.Errorf("%s: kubectl's output reached the call log", name)
		}
	}
}

// Only the API's own NotFound for this pod counts as gone; any other failure, NotFound in it or not, is unresolved.
func TestPodNotFoundIsExact(t *testing.T) {
	for name, stderr := range map[string]string{
		"another pod's NotFound": `Error from server (NotFound): pods "sandprobe-other" not found`,
		"discovery NotFound":     `error: the server could not find the requested resource (NotFound)`,
		"a namespace NotFound":   `Error from server (NotFound): namespaces "default" not found`,
	} {
		cli := func(_ context.Context, _ io.Reader, _, errw io.Writer, args ...string) error {
			io.WriteString(errw, stderr)
			return errors.New("exit status 1")
		}
		p := &PodBox{Kubeconfig: "/k", Context: "ctx-1", Name: "sandprobe-abc", UID: "uid-1", kubectl: cli}
		if err := p.Destroy(context.Background()); err == nil {
			t.Errorf("%s: read as the pod gone", name)
		}
	}
}
