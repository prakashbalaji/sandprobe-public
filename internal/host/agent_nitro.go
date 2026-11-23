package host

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"slices"
	"strings"
)

// AgentPodBinding is RUN-8's host-created, same-run workload binding. It grants no
// teardown ownership: the managed runner retains the original Job lifecycle.
type AgentPodBinding struct {
	Kubeconfig       string `json:"kubeconfig"`
	Context          string `json:"context"`
	Endpoint         string `json:"endpoint"`
	RunID            string `json:"run_id"`
	Namespace        string `json:"namespace"`
	Name             string `json:"name"`
	UID              string `json:"uid"`
	JobUID           string `json:"job_uid"`
	Image            string `json:"image"`
	ConfigSHA256     string `json:"config_sha256"`
	ContainerID      string `json:"container_id"`
	CleanEnvironment bool   `json:"clean_environment,omitempty"` // RUN-18: only the host-controller workload uses this profile.
}

var agentRun = regexp.MustCompile(`^[a-f0-9]{16}$`)
var agentUID = regexp.MustCompile(`^[a-f0-9-]{16,64}$`)
var agentName = regexp.MustCompile(`^model-task-[a-z0-9-]+$`)

// agentImage is the run's image in the operator's own ECR registry: SANDPROBE_AWS_ACCOUNT names the account the
// evaluation runs in, and an unset or malformed one matches nothing.
func agentImage(image string) bool {
	account := os.Getenv("SANDPROBE_AWS_ACCOUNT")
	if !regexp.MustCompile(`^[0-9]{12}$`).MatchString(account) {
		return false
	}
	return regexp.MustCompile(`^` + account + `\.dkr\.ecr\.us-west-2\.amazonaws\.com/sandprobe-agent-[a-f0-9]{16}@sha256:[a-f0-9]{64}$`).MatchString(image)
}

// AttachAgentPod checks the host journal's original identities before any upload.
// This is configuration evidence, not cryptographic attestation. Name-to-call
// races remain as for PodBox; only this run uses the disposable cluster.
func AttachAgentPod(ctx context.Context, b AgentPodBinding) (*PodBox, error) {
	if !agentRun.MatchString(b.RunID) || b.Namespace != "sandprobe-agent-"+b.RunID ||
		!regexp.MustCompile(`^[a-z][a-z0-9+-]*://[a-f0-9]{32,128}$`).MatchString(b.ContainerID) ||
		!agentName.MatchString(b.Name) || !agentUID.MatchString(b.UID) || !agentUID.MatchString(b.JobUID) ||
		!agentImage(b.Image) || !strings.Contains(b.Image, "/sandprobe-agent-"+b.RunID+"@") ||
		!regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(b.ConfigSHA256) ||
		!regexp.MustCompile(`^sandprobe-[a-f0-9]{8}$`).MatchString(b.Context) ||
		!strings.HasPrefix(b.Endpoint, "https://") || b.Kubeconfig == "" {
		return nil, errors.New("invalid same-run workload binding")
	}
	p := &PodBox{Kubeconfig: b.Kubeconfig, Context: b.Context, Namespace: b.Namespace, Name: b.Name, UID: b.UID, kubectl: podCLI}
	if err := p.checkAgentBinding(ctx, b); err != nil {
		return nil, err
	}
	node, err := p.run(ctx, nil, "get", "pod", b.Name, "-o", "jsonpath={.spec.nodeName}")
	if err != nil {
		return nil, errors.New("workload node unavailable")
	}
	arch, err := p.run(ctx, nil, "get", "node", string(node), "-o", "jsonpath={.status.nodeInfo.architecture}")
	if err != nil || (string(arch) != "amd64" && string(arch) != "arm64") {
		return nil, errors.New("unsupported workload architecture")
	}
	p.Arch = string(arch)
	p.agentBinding = &b
	return p, nil
}

func (p *PodBox) checkAgentBinding(ctx context.Context, b AgentPodBinding) error {
	endpoint, err := p.run(ctx, nil, "config", "view", "--minify", "-o", "jsonpath={.clusters[0].cluster.server}")
	if err != nil || string(endpoint) != b.Endpoint {
		return errors.New("workload cluster endpoint mismatch")
	}
	// Only fixed metadata/configuration fields; never fetch environment contents or tokens.
	out, err := p.run(ctx, nil, "get", "pod", b.Name, "-o", "jsonpath="+agentPodProjection())
	got := strings.Split(string(out), "\n")
	want := []string{b.UID, b.RunID, b.JobUID, "Running", "isolated-sandbox", "agent", b.Image, b.ConfigSHA256}
	if err != nil || len(got) != 12 {
		return errors.New("workload binding projection failed")
	}
	for i, value := range want {
		if got[i] != value {
			return errors.New("workload binding changed")
		}
	}
	if !regexp.MustCompile(`^[a-z0-9.-]+$`).MatchString(got[8]) {
		return errors.New("invalid workload node")
	}
	if got[11] != b.ContainerID || got[9] != "0" || !strings.HasSuffix(got[10], strings.Split(b.Image, "@")[1]) {
		return errors.New("workload container identity changed")
	}
	if b.CleanEnvironment {
		raw, err := p.run(ctx, nil, "get", "pod", b.Name, "-o", "jsonpath={.spec.containers[0].command}")
		var command []string
		want := append(WorkloadEnvironment(), "python", "-I", "-c", "import time;time.sleep(1800)")
		if err != nil || json.Unmarshal(raw, &command) != nil || !slices.Equal(command, want) {
			return errors.New("workload clean-environment command changed")
		}
	}
	return nil
}

func agentPodProjection() string {
	fields := []string{".metadata.uid", ".metadata.labels.sandprobe\\.run", ".metadata.ownerReferences[?(@.controller==true)].uid",
		".status.phase", ".spec.runtimeClassName", ".spec.containers[0].name", ".spec.containers[0].image",
		`.spec.containers[0].env[?(@.name=="SANDPROBE_CONFIG_SHA256")].value`, ".spec.nodeName", ".status.containerStatuses[0].restartCount", ".status.containerStatuses[0].imageID", ".status.containerStatuses[0].containerID"}
	parts := make([]string, len(fields))
	for i, field := range fields {
		parts[i] = "{" + field + "}"
	}
	return strings.Join(parts, `{"\n"}`)
}
