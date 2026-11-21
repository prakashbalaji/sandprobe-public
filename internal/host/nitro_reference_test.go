package host

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"slices"
	"strings"
	"testing"
	"text/template"
)

const testReferenceID = "containerd://sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func referencePod(t *testing.T, network bool) map[string]any {
	t.Helper()
	var pod map[string]any
	if err := json.Unmarshal(manifest("sandprobe-ref", PodSpec{Image: ReferenceImage, RuntimeClass: "isolated-sandbox", Reference: true, NetworkIsolated: network}), &pod); err != nil {
		t.Fatal(err)
	}
	pod["metadata"].(map[string]any)["uid"] = "uid-1"
	pod["status"] = map[string]any{"containerStatuses": []map[string]string{{"imageID": testReferenceID}}}
	return pod
}

func refContainer(pod map[string]any) map[string]any {
	return pod["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)
}

func templateKube(t *testing.T, pod map[string]any, fallback *fakeKube) func(context.Context, io.Reader, io.Writer, io.Writer, ...string) error {
	t.Helper()
	return func(ctx context.Context, in io.Reader, out, errOut io.Writer, args ...string) error {
		for _, arg := range args {
			if source, ok := strings.CutPrefix(arg, "go-template="); ok {
				tmpl, err := template.New("safe-projection").Option("missingkey=zero").Parse(source)
				if err != nil {
					return err
				}
				return tmpl.Execute(out, pod)
			}
		}
		return fallback.cli(ctx, in, out, errOut, args...)
	}
}

func TestReferenceManifestPair(t *testing.T) {
	open, isolated := referencePod(t, false), referencePod(t, true)
	delete(isolated["metadata"].(map[string]any), "annotations")
	if !reflect.DeepEqual(open, isolated) {
		t.Fatal("pair differs beyond network annotation")
	}
	spec := open["spec"].(map[string]any)
	c := refContainer(open)
	sc := spec["securityContext"].(map[string]any)
	if sc["runAsUser"] != float64(10001) || sc["runAsGroup"] != float64(10001) || sc["fsGroup"] != float64(10001) || sc["runAsNonRoot"] != true || c["image"] != ReferenceImage {
		t.Fatal("wrong reference identity or image")
	}
	if c["command"].([]any)[2] != referenceTask || c["workingDir"] != "/workspace" || spec["automountServiceAccountToken"] != false || spec["enableServiceLinks"] != false {
		t.Fatal("workload or credential scope changed")
	}
	var legacy map[string]any
	_ = json.Unmarshal(manifest("old", PodSpec{Image: "old-image", RuntimeClass: "isolated-sandbox"}), &legacy)
	oldSpec := legacy["spec"].(map[string]any)
	if _, added := oldSpec["securityContext"]; added || len(oldSpec) != 3 {
		t.Fatal("default configuration changed")
	}
}

func TestReferenceSnapshotAccepted(t *testing.T) {
	for _, network := range []bool{false, true} {
		f := &fakeKube{uids: []string{"uid-1"}}
		orig := podCLI
		podCLI = templateKube(t, referencePod(t, network), f)
		p, err := CreatePod(context.Background(), "/k", "ctx-1", PodSpec{Image: ReferenceImage, RuntimeClass: "isolated-sandbox", Reference: true, NetworkIsolated: network})
		podCLI = orig
		if err != nil || p.ReferenceImageID != testReferenceID {
			t.Fatalf("reference rejected: %v", err)
		}
		if !slices.ContainsFunc(f.calls, func(a []string) bool { return slices.Contains(a, "--timeout=2m") }) {
			t.Fatal("reference readiness unbounded")
		}
		f.uids = []string{"uid-1"}
		p.ProbePath = "/tmp/probe"
		if _, err = p.Probe(context.Background(), []string{"-survey"}, nil); err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(f.calls[len(f.calls)-1], "HOME=/workspace") {
			t.Fatal("probe and workload HOME differ")
		}
	}
}

func TestReferenceAcceptsUnrelatedAnnotations(t *testing.T) {
	for _, network := range []bool{false, true} {
		pod := referencePod(t, network)
		metadata := pod["metadata"].(map[string]any)
		annotations, _ := metadata["annotations"].(map[string]any)
		if annotations == nil {
			annotations = map[string]any{}
			metadata["annotations"] = annotations
		}
		annotations["example.test/unrelated"] = "present"
		p := &PodBox{Kubeconfig: "/k", Context: "ctx-1", Name: "sandprobe-ref", UID: "uid-1", kubectl: templateKube(t, pod, &fakeKube{})}
		if err := p.verifyReference(context.Background(), PodSpec{Image: ReferenceImage, RuntimeClass: "isolated-sandbox", Reference: true, NetworkIsolated: network}); err != nil {
			t.Fatalf("unrelated annotation rejected: %v", err)
		}
	}
}

func TestReferenceRejectsAdmissionChanges(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(map[string]any)
	}{
		{"wrong-uid", func(p map[string]any) { p["metadata"].(map[string]any)["uid"] = "other" }},
		{"root", func(p map[string]any) {
			p["spec"].(map[string]any)["securityContext"].(map[string]any)["runAsUser"] = 0
		}},
		{"host-network", func(p map[string]any) { p["spec"].(map[string]any)["hostNetwork"] = true }},
		{"host-pid", func(p map[string]any) { p["spec"].(map[string]any)["hostPID"] = true }},
		{"host-ipc", func(p map[string]any) { p["spec"].(map[string]any)["hostIPC"] = true }},
		{"privileged", func(p map[string]any) { refContainer(p)["securityContext"].(map[string]any)["privileged"] = true }},
		{"env-injected", func(p map[string]any) {
			refContainer(p)["env"] = []any{map[string]any{"name": "API_KEY", "value": "DO_NOT_LEAK_SECRET"}}
		}},
		{"envfrom-injected", func(p map[string]any) {
			refContainer(p)["envFrom"] = []any{map[string]any{"secretRef": map[string]any{"name": "private"}}}
		}},
		{"image-mutated", func(p map[string]any) { refContainer(p)["image"] = "unapproved" }},
		{"command-mutated", func(p map[string]any) { refContainer(p)["command"] = []string{"sleep", "infinity"} }},
		{"extra-args", func(p map[string]any) { refContainer(p)["args"] = []string{"extra"} }},
		{"lifecycle-hook", func(p map[string]any) {
			refContainer(p)["lifecycle"] = map[string]any{"postStart": map[string]any{"exec": map[string]any{"command": []string{"true"}}}}
		}},
		{"extra-startup-probe", func(p map[string]any) {
			refContainer(p)["startupProbe"] = map[string]any{"exec": map[string]any{"command": []string{"true"}}}
		}},
		{"extra-liveness-probe", func(p map[string]any) {
			refContainer(p)["livenessProbe"] = map[string]any{"exec": map[string]any{"command": []string{"true"}}}
		}},
		{"mount-subpath", func(p map[string]any) {
			refContainer(p)["volumeMounts"].([]any)[0].(map[string]any)["subPath"] = "changed"
		}},
		{"mount-subpath-expr", func(p map[string]any) {
			refContainer(p)["volumeMounts"].([]any)[0].(map[string]any)["subPathExpr"] = "changed"
		}},
		{"mount-propagation", func(p map[string]any) {
			refContainer(p)["volumeMounts"].([]any)[0].(map[string]any)["mountPropagation"] = "Bidirectional"
		}},
		{"mount-readonly", func(p map[string]any) { refContainer(p)["volumeMounts"].([]any)[0].(map[string]any)["readOnly"] = true }},
		{"emptydir-medium", func(p map[string]any) {
			p["spec"].(map[string]any)["volumes"].([]any)[0].(map[string]any)["emptyDir"].(map[string]any)["medium"] = "Memory"
		}},
		{"container-user-override-zero", func(p map[string]any) { refContainer(p)["securityContext"].(map[string]any)["runAsUser"] = 0 }},
		{"container-group-override-zero", func(p map[string]any) { refContainer(p)["securityContext"].(map[string]any)["runAsGroup"] = 0 }},
		{"extra-caps", func(p map[string]any) {
			refContainer(p)["securityContext"].(map[string]any)["capabilities"].(map[string]any)["add"] = []string{"SYS_ADMIN"}
		}},
		{"missing-readonly", func(p map[string]any) {
			delete(refContainer(p)["securityContext"].(map[string]any), "readOnlyRootFilesystem")
		}},
		{"extra-container", func(p map[string]any) {
			s := p["spec"].(map[string]any)
			s["containers"] = append(s["containers"].([]any), map[string]any{"name": "injected"})
		}},
		{"extra-volume", func(p map[string]any) {
			s := p["spec"].(map[string]any)
			s["volumes"] = append(s["volumes"].([]any), map[string]any{"name": "secret", "secret": map[string]any{"secretName": "private"}})
		}},
		{"service-token", func(p map[string]any) { p["spec"].(map[string]any)["automountServiceAccountToken"] = true }},
		{"init-container", func(p map[string]any) {
			p["spec"].(map[string]any)["initContainers"] = []any{map[string]any{"name": "injected"}}
		}},
		{"ephemeral-container", func(p map[string]any) {
			p["spec"].(map[string]any)["ephemeralContainers"] = []any{map[string]any{"name": "injected"}}
		}},
		{"missing-image-id", func(p map[string]any) { delete(p, "status") }},
		{"bad-image-id", func(p map[string]any) {
			p["status"] = map[string]any{"containerStatuses": []map[string]string{{"imageID": "unsafe\nDO_NOT_LEAK_SECRET"}}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := referencePod(t, false)
			tc.edit(pod)
			f := &fakeKube{}
			p := &PodBox{Kubeconfig: "/k", Context: "ctx-1", Name: "sandprobe-ref", UID: "uid-1", kubectl: templateKube(t, pod, f)}
			err := p.verifyReference(context.Background(), PodSpec{Image: ReferenceImage, Reference: true, RuntimeClass: "isolated-sandbox"})
			if err == nil || p.ReferenceImageID != "" || strings.Contains(err.Error(), "DO_NOT_LEAK") {
				t.Fatal("mutation accepted or leaked")
			}
		})
	}
}

func TestReferenceVerificationFailureLeavesCleanupHandle(t *testing.T) {
	pod := referencePod(t, false)
	refContainer(pod)["image"] = "mutated"
	f := &fakeKube{uids: []string{"uid-1", "uid-1", ""}}
	orig := podCLI
	defer func() { podCLI = orig }()
	podCLI = templateKube(t, pod, f)
	p, err := CreatePod(context.Background(), "/k", "ctx-1", PodSpec{Image: ReferenceImage, RuntimeClass: "isolated-sandbox", Reference: true})
	if err == nil || p.UID != "uid-1" {
		t.Fatal("lost cleanup handle")
	}
	if err = p.Destroy(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(f.calls, func(a []string) bool { return a[0] == "delete" }) {
		t.Fatal("no delete on verification failure")
	}
}

func TestReferenceRejectsUnpinnedProfileBeforeCreate(t *testing.T) {
	orig := podCLI
	defer func() { podCLI = orig }()
	called := false
	podCLI = func(context.Context, io.Reader, io.Writer, io.Writer, ...string) error {
		called = true
		return errors.New("must not create")
	}
	_, err := CreatePod(context.Background(), "/k", "ctx-1", PodSpec{Image: "mutable:tag", RuntimeClass: "isolated-sandbox", Reference: true})
	if err == nil || called {
		t.Fatal("unfixed reference configuration created")
	}
}

func TestReferenceProjectionDoesNotExportInjectedValues(t *testing.T) {
	pod := referencePod(t, false)
	refContainer(pod)["env"] = []any{map[string]any{"name": "KEY", "value": "DO_NOT_LEAK_SECRET"}}
	var out bytes.Buffer
	fields := referenceFields("uid-1", PodSpec{Image: ReferenceImage})
	for _, field := range fields {
		tmpl, err := template.New("projection").Option("missingkey=zero").Parse(field.expression)
		if err != nil {
			t.Fatal(err)
		}
		if err = tmpl.Execute(&out, pod); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Contains(out.String(), "DO_NOT_LEAK") {
		t.Fatal("projection exported env value")
	}
}

func TestReferenceTemplateErrorDoesNotLeakRawDebugData(t *testing.T) {
	p := &PodBox{Kubeconfig: "/k", Context: "ctx-1", Name: "sandprobe-ref", UID: "uid-1",
		kubectl: func(_ context.Context, _ io.Reader, _ io.Writer, stderr io.Writer, _ ...string) error {
			io.WriteString(stderr, "raw Pod debug data: DO_NOT_LEAK_SECRET")
			return errors.New("template failure DO_NOT_LEAK_SECRET")
		}}
	err := p.verifyReference(context.Background(), PodSpec{Image: ReferenceImage, Reference: true, RuntimeClass: "isolated-sandbox"})
	if err == nil || strings.Contains(err.Error(), "DO_NOT_LEAK") {
		t.Fatal("raw template error escaped")
	}
	b, _ := json.Marshal(p.Calls)
	if bytes.Contains(b, []byte("DO_NOT_LEAK")) {
		t.Fatal("raw debug data recorded")
	}
}
