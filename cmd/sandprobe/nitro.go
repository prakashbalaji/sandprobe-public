package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"sandprobe/internal/catalog"
	"sandprobe/internal/host"
	"sandprobe/internal/obs"
	"sandprobe/internal/probes"
	"sandprobe/internal/report"
)

// nitroResidual is what the Nitro adapter leaves that no check closes (PRV-1).
const nitroResidual = "Pods are reached by name (the readiness check, the upload, the probe, the delete), each once their UID is " +
	"checked; the race between a check and its call is residual, though only Sandprobe uses the cluster, so no one else can reuse " +
	"the name. The cluster itself stays until deploy/eks.sh down deletes it."

// podImage is the EKS docs' own example of an isolated pod (PRV table).
const podImage = "public.ecr.aws/amazonlinux/amazonlinux:2023"

// eksTarget is the only EKS deployment deploy/eks.sh recorded: its kubeconfig and the context named for its cluster,
// bound to the cluster by the API endpoint recorded when the cluster was made, so no edit to the kubeconfig can send a
// run to another cluster.
func eksTarget() (kc, context string, err error) {
	found, _ := filepath.Glob(filepath.Join(configDir(), "eks-*.state"))
	if len(found) != 1 {
		return "", "", fail("not_logged_in", "no single EKS cluster of Sandprobe's own found", "deploy/eks.sh up", exitLogin)
	}
	b, err := os.ReadFile(found[0])
	if err != nil {
		return "", "", fail("not_logged_in", "the EKS state can't be read", "deploy/eks.sh status", exitLogin)
	}
	kv := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			kv[k] = v
		}
	}
	kc, context = kv["kubeconfig"], kv["cluster"]
	if kc == "" || context == "" || kv["endpoint"] == "" {
		return "", "", fail("not_logged_in", "the EKS deployment isn't whole yet", "deploy/eks.sh status", exitLogin)
	}
	if err := bindContext(kc, context, kv["endpoint"]); err != nil {
		return "", "", fail("not_logged_in", err.Error(), "deploy/eks.sh status", exitLogin)
	}
	if exec.Command("kubectl", "--kubeconfig", kc, "--context", context, "get", "runtimeclass", "isolated-sandbox", "-o", "name").Run() != nil {
		return "", "", fail("not_logged_in", "the cluster doesn't answer, or offers no isolated-sandbox runtime class", "deploy/eks.sh status", exitLogin)
	}
	return kc, context, nil
}

// bindContext checks the kubeconfig's context for the cluster points at the API endpoint recorded for it.
func bindContext(kc, context, endpoint string) error {
	out, err := exec.Command("kubectl", "--kubeconfig", kc, "config", "view", "--minify", "--context", context,
		"-o", "jsonpath={.clusters[0].cluster.server}").Output()
	if err != nil {
		return fmt.Errorf("the kubeconfig has no context %s", context)
	}
	if got := strings.TrimSpace(string(out)); got != endpoint {
		return fmt.Errorf("the kubeconfig's context %s points at %s, not the recorded %s", context, got, endpoint)
	}
	return nil
}

func nitroSpec(variant string) (host.PodSpec, error) {
	switch variant {
	case "isolated":
		return host.PodSpec{Image: podImage, RuntimeClass: "isolated-sandbox"}, nil
	case "network-isolated":
		return host.PodSpec{Image: podImage, RuntimeClass: "isolated-sandbox", NetworkIsolated: true}, nil
	case "reference-open", "reference-network-isolated":
		return host.PodSpec{Image: host.ReferenceImage, RuntimeClass: "isolated-sandbox", Reference: true, NetworkIsolated: variant == "reference-network-isolated"}, nil
	}
	return host.PodSpec{}, fail("usage", "-variant takes isolated, network-isolated, reference-open or reference-network-isolated", "sandprobe run aws-nitro -variant isolated -y", exitUsage)
}

func nitroPlan(kc string, c canaryChoice, r runFlags, spec host.PodSpec) planDoc {
	sec3, _ := catalog.Get("SEC-3")
	pod := "a pod sandprobe-<12 hex> in Sandprobe's own EKS Auto Mode cluster: " + spec.Image + ", runtimeClassName " + spec.RuntimeClass
	if spec.NetworkIsolated {
		pod += ", sandbox.amazonaws.com/network-isolated: \"true\""
	}
	launch := "kubectl exec -i, as the container's default user, with Sandprobe's kubeconfig " + kc
	runs := []string{"sudo -n -l, which runs no command and may be logged"}
	if spec.Reference {
		pod += "; reference UID/GID10001, drop ALL capabilities, no privilege escalation, RuntimeDefault seccomp, read-only root, no service token or service links; /tmp and /workspace emptyDir64Mi each"
		launch += "; reference user10001, HOME=/workspace; API configuration checked before probe upload"
		runs = append(runs, "fixed nonsecret text transform/checksum task in /workspace, completion-gated readiness; deterministic shell task, not an LLM/coding agent")
	}
	proxy := "no: EGR-3 is skipped if the box names a local proxy (approve one with -allow-local-proxy)"
	if r.allowLocalProxy {
		proxy = "yes: EGR-3 may use a proxy on the box's own loopback, if the box names one"
	}
	return planDoc{Provider: "aws-nitro (" + r.variant + ")",
		Creates:    []string{pod, "an Auto Mode node for it, if none is free (the cluster's own; it goes with the cluster)"},
		LaunchPath: launch,
		Probe:      "uploaded to /tmp/sandprobe-<12 hex>/probe in the pod, with its scratch directory; both go with the pod",
		Markers:    "none: the pod has no persistent volume, so PER-5 is skipped",
		Contacts: []string{
			c.describe,
			"its DNS names, looked up through the pod's own resolver",
			"169.254.169.254:80, cloud metadata (AWS and GCP); 169.254.170.2:80 and 169.254.170.23:80 only if the pod's environment names them",
		},
		BoxNamed: []string{"the proxy the agent's environment names, for EGR-3 only", "the Kubernetes API the agent's environment names, for AMP-7 only: a TLS handshake, no request"},
		OpensReadOnly: append(append([]string{}, sec3.Targets...),
			"private SSH keys, /run/secrets (four levels deep) and .env files it finds", "/proc/<pid>/environ and /proc/<pid>/mem of other processes"),
		Runs:       runs,
		Reset:      "none: the default pod has no persistent volume, so PER-5 is skipped",
		Deletes:    "the pod, by name once its UID is checked; the cluster stays until deploy/eks.sh down",
		LocalProxy: proxy,
		Time:       "a few minutes when Auto Mode has to start a node for the pod; under a minute when one is free",
		Residual:   withRetention(nitroResidual, c),
	}
}

func runNitro(o opts, r runFlags, plan bool, stderr io.Writer) (int, error) {
	spec, err := nitroSpec(r.variant)
	if err != nil {
		return 0, err
	}
	choice, err := r.chooseCanary()
	if err != nil {
		return 0, err
	}
	kc, kctx, err := eksTarget()
	if err != nil {
		return 0, err
	}
	p := nitroPlan(kc+" (context "+kctx+")", choice, r, spec)
	if plan {
		if o.json() {
			o.emit(p)
		} else {
			printPlan(o.stdout, p)
		}
		return 0, nil
	}
	switch {
	case o.yes:
	case o.tty():
		printPlan(o.stdout, p)
		fmt.Fprint(o.stdout, "\nCreate the pod, run and delete it? [y/N] ")
		answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" {
			return exitApproval, fail("needs_approval", "nothing was created: the plan wasn't approved", "sandprobe run aws-nitro -y", exitApproval)
		}
	default:
		p.NeedsApproval = true
		if o.json() {
			o.emit(p)
		} else {
			printPlan(o.stdout, p)
			fmt.Fprintln(stderr, "\nsandprobe: nothing was created. Show your person this plan, then run again with -y.")
		}
		return exitApproval, nil
	}
	if _, _, err := probes.Probe("amd64"); err != nil { // stop before creating anything when the build carries no probe
		return 0, fail("usage", err.Error(), "make", exitUsage)
	}
	step := func(f string, a ...any) {
		if !o.json() {
			fmt.Fprintf(stderr, "· "+f+"\n", a...)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	c, public, err := r.openCanary(ctx, choice, step) // HCN-5: proven, and its slot reserved, before the pod exists
	if err != nil {
		return 0, err
	}
	defer closeCanary(public, stderr)
	start := time.Now()
	step("creating the pod (Auto Mode may start a node for it)")
	pod, err := host.CreatePod(ctx, kc, kctx, spec)
	cleanup, cleaned := "the pod was deleted, the API confirming it gone", true
	teardown := func() {
		tctx, tcancel := context.WithTimeout(context.Background(), 6*time.Minute) // even after Ctrl-C
		defer tcancel()
		step("deleting pod %s", pod.Name)
		if terr := pod.Destroy(tctx); terr != nil {
			cleanup, cleaned = fmt.Sprintf("NOT confirmed deleted: delete pod %s (%s) by hand, or run deploy/eks.sh down", pod.Name, pod.UID), false
			fmt.Fprintf(stderr, "sandprobe: %s\n  %v\n", cleanup, terr)
		}
	}
	if err != nil {
		teardown()
		return 0, fail("provider_error", err.Error(), "deploy/eks.sh status", failExit(cleaned))
	}
	var run *host.Run
	bin, sum, err := probes.Probe(pod.Arch)
	if err == nil {
		step("pod %s (%s) on %s; uploading the probe", pod.Name, pod.UID, pod.Arch)
		err = pod.Upload(ctx, bin)
	}
	if err == nil {
		step("running the probe as the agent")
		var contract *obs.BoundaryContract
		contract, err = host.ReferenceBoundary(spec, pod.ReferenceImageID)
		if err == nil {
			run, err = host.Execute(ctx, pod, c, host.Options{Mode: "exec", ProbeSHA256: sum, AllowLocalProxy: r.allowLocalProxy, BoundaryContract: contract})
		}
	}
	teardown()
	if err != nil {
		return 0, fail("provider_error", err.Error(), "see the message; the pod's cleanup is above", failExit(cleaned))
	}
	d := report.Build(run, report.Meta{Version: Version, Provider: "aws-nitro", BoxName: pod.Name + " (" + r.variant + ")",
		CreatedBySandprobe: true, StartedAt: start, Duration: time.Since(start), Calls: pod.Calls, Cleanup: cleanup, Residual: nitroResidual})
	if spec.Reference {
		d.Grade.Notes = append(d.Grade.Notes, "REF-3: operator-hardened "+r.variant+"; requested image "+spec.Image+"; Kubernetes-reported image ID "+pod.ReferenceImageID+". API configuration checked, not kernel enforcement attestation.",
			"REF-2: requested UID/GID10001, drop ALL caps, no privilege escalation, RuntimeDefault seccomp, read-only root, no service-token mount or service links, ephemeral /tmp and /workspace64Mi each; HOME=/workspace; deterministic file task, not an LLM workload. Probe identity/findings remain unchanged; no passing grade is promised.")
	}
	return finish(o, r, d, cleaned)
}
