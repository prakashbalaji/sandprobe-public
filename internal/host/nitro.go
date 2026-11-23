package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"sandprobe/internal/obs"
)

// PodSpec is the pod a Nitro run grades: the docs' own example, in isolated mode, with or without its network.
type PodSpec struct {
	Image           string // public.ecr.aws/amazonlinux/amazonlinux:2023
	RuntimeClass    string // isolated-sandbox
	NetworkIsolated bool   // sandbox.amazonaws.com/network-isolated: "true"
	Reference       bool   // REF-1: explicit hardened file-task configuration, not provider defaults
}

// PodBox is a pod in Sandprobe's own EKS cluster, reached with `kubectl exec -i` as its container's default user, the
// way isolated mode lets the parent reach its workload (PRV table: AWS Nitro). Sandprobe creates it for the run and
// deletes it after, by name once its UID is checked; nobody else uses the cluster, so no one else can reuse the name.
type PodBox struct {
	Kubeconfig, Context string // Sandprobe's own kubeconfig, and the recorded cluster's context in it, named on every call
	Namespace           string // RUN-8: explicit namespace for an attached workload; empty preserves default adapters
	Name, UID           string
	Arch                string // the node's, from the Kubernetes API: amd64 or arm64
	ProbePath           string
	ReferenceImageID    string // REF-3: API-reported immutable image ID, not enforcement attestation
	Calls               []obs.ProviderCall
	agentBinding        *AgentPodBinding // RUN-8: rechecked before each upload/probe
	kubectl             func(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, args ...string) error
}

// podCLI, when set, stands in for kubectl in pods CreatePod makes; tests set it.
var podCLI func(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, args ...string) error

func manifest(name string, spec PodSpec) []byte {
	pod := map[string]any{"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": name, "namespace": "default", "labels": map[string]string{"app.kubernetes.io/managed-by": "sandprobe"}},
		"spec": map[string]any{"runtimeClassName": spec.RuntimeClass, "restartPolicy": "Never",
			"containers": []map[string]any{{"name": "agent", "image": spec.Image, "command": []string{"sleep", "infinity"},
				"resources": map[string]any{"limits": map[string]string{"cpu": "1", "memory": "1Gi"}}}}}}
	if spec.NetworkIsolated {
		pod["metadata"].(map[string]any)["annotations"] = map[string]string{"sandbox.amazonaws.com/network-isolated": "true"}
	}
	if spec.Reference {
		referenceManifest(pod)
	}
	b, _ := json.Marshal(pod)
	return b
}

// CreatePod creates the run's pod and waits for it to be ready. It always returns the box, so a create that failed
// after the API made the pod still leaves its name for Destroy to resolve.
func CreatePod(ctx context.Context, kubeconfig, kubeContext string, spec PodSpec) (*PodBox, error) {
	p := &PodBox{Kubeconfig: kubeconfig, Context: kubeContext, Name: "sandprobe-" + token("")[1:13], kubectl: podCLI}
	if spec.Reference && (spec.Image != ReferenceImage || spec.RuntimeClass != "isolated-sandbox") {
		return p, errors.New("reference profile requires the fixed image and runtime")
	}
	out, err := p.run(ctx, bytes.NewReader(manifest(p.Name, spec)), "create", "-f", "-", "-o", "jsonpath={.metadata.uid}")
	if err != nil {
		return p, fmt.Errorf("creating pod %s: %w", p.Name, err)
	}
	if p.UID = strings.TrimSpace(string(out)); p.UID == "" {
		return p, fmt.Errorf("pod %s was created, but its UID didn't come back", p.Name)
	}
	if n := len(p.Calls); n > 0 {
		p.Calls[n-1].ID = p.UID
	}
	wait := "--timeout=15m"
	if spec.Reference {
		// REF-2: allow node provisioning, then bound task readiness separately.
		if _, err := p.run(ctx, nil, "wait", "pod/"+p.Name, "--for=condition=PodScheduled", "--timeout=15m"); err != nil {
			return p, errors.New("reference pod was not scheduled within its deadline")
		}
		wait = "--timeout=2m"
	}
	if _, err := p.run(ctx, nil, "wait", "pod/"+p.Name, "--for=condition=Ready", wait); err != nil {
		return p, fmt.Errorf("pod %s never became ready: %w", p.Name, err)
	}
	node, err := p.run(ctx, nil, "get", "pod", p.Name, "-o", "jsonpath={.spec.nodeName}")
	if err != nil {
		return p, err
	}
	arch, err := p.run(ctx, nil, "get", "node", strings.TrimSpace(string(node)), "-o", "jsonpath={.status.nodeInfo.architecture}")
	if err != nil {
		return p, err
	}
	p.Arch = strings.TrimSpace(string(arch))
	// A new node's kubelet serves exec only once its serving certificate is issued, a little after the pod is ready.
	for i := 0; ; i++ {
		if err := p.ours(ctx); err != nil { // even a readiness exec reaches the pod by name (PRV-1)
			return p, err
		}
		_, err := p.run(ctx, nil, "exec", p.Name, "-c", "agent", "--", "true")
		switch {
		case err == nil:
			if spec.Reference {
				if err := p.verifyReference(ctx, spec); err != nil {
					return p, err
				}
			}
			return p, nil
		case i == 24 || !strings.Contains(err.Error(), "error dialing backend"):
			return p, fmt.Errorf("pod %s doesn't take exec: %w", p.Name, err)
		}
		select {
		case <-ctx.Done():
			return p, ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

func (p *PodBox) ID() string { return p.UID }

// ours checks, immediately before a call that reaches the pod by name, that the name still has the UID the create
// returned (PRV-1).
func (p *PodBox) ours(ctx context.Context) error {
	uid, gone, err := p.lookup(ctx)
	switch {
	case err != nil:
		return err
	case gone:
		return fmt.Errorf("pod %s is gone", p.Name)
	case p.UID == "" || uid != p.UID:
		return fmt.Errorf("pod %s has UID %s, not this run's %s: left alone", p.Name, uid, p.UID)
	}
	if p.agentBinding != nil {
		return p.checkAgentBinding(ctx, *p.agentBinding)
	}
	return nil
}

func (p *PodBox) lookup(ctx context.Context) (uid string, gone bool, err error) {
	var errs bytes.Buffer
	out, err := p.runErr(ctx, nil, &errs, "get", "pod", p.Name, "-o", "jsonpath={.metadata.uid}")
	switch {
	case err == nil:
		return strings.TrimSpace(string(out)), false, nil
	case strings.Contains(errs.String(), `(NotFound): pods "`+p.Name+`" not found`): // the API's own answer for this pod,
		return "", true, nil // read but never recorded; any other failure, NotFound in it or not, stays unresolved
	}
	return "", false, fmt.Errorf("looking up pod %s: %w", p.Name, err)
}

// Upload puts the probe in a fresh directory in the pod, as its default user, and checks the bytes arrived whole.
func (p *PodBox) Upload(ctx context.Context, probe []byte) error {
	if err := p.ours(ctx); err != nil {
		return err
	}
	dir := "/tmp/sandprobe-" + token("")[1:13]
	sum := sha256.Sum256(probe)
	out, err := p.run(ctx, bytes.NewReader(probe), "exec", "-i", p.Name, "-c", "agent", "--", "sh", "-c",
		fmt.Sprintf("umask 022 && mkdir %s && cat > %s/probe && chmod 0555 %s/probe && sha256sum %s/probe", dir, dir, dir, dir))
	if err != nil {
		return fmt.Errorf("uploading the probe: %w", err)
	}
	if got, _, _ := strings.Cut(strings.TrimSpace(string(out)), " "); got != hex.EncodeToString(sum[:]) {
		return fmt.Errorf("the probe arrived as %q, not %x", got, sum)
	}
	p.ProbePath = dir + "/probe"
	return nil
}

// Probe runs the probe as the container's default user. SANDPROBE_TWIN is SEC-1's twin, set on the way in.
func (p *PodBox) Probe(ctx context.Context, args []string, stdin []byte) ([]byte, error) {
	if p.ProbePath == "" {
		return nil, errors.New("the probe isn't uploaded")
	}
	for _, a := range args {
		if !probeArg.MatchString(a) {
			return nil, fmt.Errorf("not a probe argument: %q", a)
		}
	}
	if err := p.ours(ctx); err != nil {
		return nil, err
	}
	prefix := []string{"exec", "-i", p.Name, "-c", "agent", "--", "env", "SANDPROBE_TWIN=1"}
	if p.agentBinding != nil && p.agentBinding.CleanEnvironment {
		prefix = append([]string{"exec", "-i", p.Name, "-c", "agent", "--"}, WorkloadEnvironment()...)
	}
	if p.ReferenceImageID != "" {
		prefix = append(prefix, "HOME=/workspace")
	}
	prefix = append(prefix, p.ProbePath)
	return p.run(ctx, bytes.NewReader(stdin), append(prefix, args...)...)
}

// Destroy deletes the pod by name while it has the UID the create returned, and confirms the API's NotFound after.
// A pod already gone counts as deleted; one whose create never returned a UID is reported, never deleted.
func (p *PodBox) Destroy(ctx context.Context) error {
	uid, gone, err := p.lookup(ctx)
	switch {
	case err != nil:
		return err
	case gone:
		return nil
	case p.UID == "":
		return fmt.Errorf("pod %s exists (%s), but this run's create never confirmed it: left alone, unresolved", p.Name, uid)
	case uid != p.UID:
		return fmt.Errorf("pod %s has UID %s, not %s: left alone", p.Name, uid, p.UID)
	}
	if _, err := p.run(ctx, nil, "delete", "pod", p.Name, "--wait=true", "--timeout=5m"); err != nil {
		return fmt.Errorf("deleting pod %s: %w", p.Name, err)
	}
	if _, gone, err := p.lookup(ctx); err != nil || !gone {
		return fmt.Errorf("pod %s (%s) still answers after its delete", p.Name, p.UID)
	}
	return nil
}

func (p *PodBox) run(ctx context.Context, stdin io.Reader, args ...string) ([]byte, error) {
	return p.runErr(ctx, stdin, nil, args...)
}

// runErr calls kubectl with Sandprobe's own kubeconfig, keeps stdout (capped like a document), hands stderr to the
// caller when it asks, and records the call without either (PRV-3).
func (p *PodBox) runErr(ctx context.Context, stdin io.Reader, errOut io.Writer, args ...string) ([]byte, error) {
	if stdin == nil {
		stdin = bytes.NewReader(nil)
	}
	full := append([]string{"--kubeconfig", p.Kubeconfig, "--context", p.Context}, args...)
	if p.Namespace != "" {
		full = append([]string{"--kubeconfig", p.Kubeconfig, "--context", p.Context, "--namespace", p.Namespace}, args...)
	}
	out, errs := &capped{max: obs.MaxDoc + 1}, &capped{max: 4 << 10}
	at := time.Now()
	var err error
	if p.kubectl != nil {
		err = p.kubectl(ctx, stdin, out, errs, full...)
	} else {
		cmd := exec.CommandContext(ctx, "kubectl", full...)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, out, errs
		err = cmd.Run()
	}
	c := callRecord(ctx, at, args, "", err)
	c.Call = "kubectl --context " + p.Context + " " + strings.Join(args, " ") // PRV-3: which cluster, on the record
	p.Calls = append(p.Calls, c)
	if errOut != nil {
		errOut.Write(errs.Bytes())
	}
	if err != nil { // stderr reaches the operator's terminal through the error, never the call record or a report
		return out.Bytes(), fmt.Errorf("kubectl %s: %w: %s", args[0], err, strings.TrimSpace(errs.String()))
	}
	return out.Bytes(), nil
}
